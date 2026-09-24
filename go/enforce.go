package gentrail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// Decision values the backend's decide endpoint returns for a proposed tool
// call.
const (
	DecisionAllow = "ALLOW"
	DecisionBlock = "BLOCK"
	DecisionGate  = "GATE"
)

// Gate statuses AwaitGate resolves to. Anything but GateApproved means the
// gated tool call must stay cancelled.
const (
	GateApproved = "approved"
	GateDenied   = "denied"
	GateExpired  = "expired"
	GateTimeout  = "timeout"
)

const (
	defaultDecideTimeout    = 3 * time.Second
	defaultGateTimeout      = 120 * time.Second
	defaultGatePollInterval = 2 * time.Second
)

// Identify the client on every request. Go's default "Go-http-client/1.1"
// reads as a bot to edge WAFs (e.g. Cloudflare fronting the backend answers
// 403), which would silently fail-open enforcement; a named agent is allowed
// through.
const enforcerUserAgent = "gentrail-sdk-go"

// Verdict is the backend's decision for a proposed tool call.
type Verdict struct {
	Decision string    `json:"decision"`
	Rule     string    `json:"rule,omitempty"`
	Message  string    `json:"message,omitempty"`
	Approval *Approval `json:"approval,omitempty"`
}

// Approval locates the human-approval hold a GATE verdict created. Pass it to
// AwaitGate to wait for the human's decision.
type Approval struct {
	StatusURL string `json:"status_url"`
}

// Enforcer is a synchronous client for the backend's /api/v1/decide endpoint.
// The async evaluator only sees a trace after the tool already ran, so it can
// detect but never prevent; enforcement happens here, before the call
// executes. A nil Enforcer allows every call, so the default behaviour stays
// observe-only.
type Enforcer struct {
	base         string
	apiKey       string
	client       *http.Client
	gateTimeout  time.Duration
	pollInterval time.Duration
}

// NewEnforcer builds an Enforcer for the dashboard at endpoint (base URL, no
// path suffix), authenticating with apiKey. The default gate wait of 120s can
// be overridden with GENTRAIL_GATE_TIMEOUT_SECONDS.
func NewEnforcer(endpoint, apiKey string) *Enforcer {
	gateTimeout := defaultGateTimeout
	if v := os.Getenv("GENTRAIL_GATE_TIMEOUT_SECONDS"); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
			gateTimeout = time.Duration(secs * float64(time.Second))
		}
	}
	return &Enforcer{
		base:         strings.TrimRight(endpoint, "/"),
		apiKey:       apiKey,
		client:       &http.Client{Timeout: defaultDecideTimeout},
		gateTimeout:  gateTimeout,
		pollInterval: defaultGatePollInterval,
	}
}

// NewEnforcerFromEnv builds an Enforcer from GENTRAIL_DECIDE_ENDPOINT and
// GENTRAIL_API_KEY. Returns nil when either is unset.
func NewEnforcerFromEnv() *Enforcer {
	endpoint := strings.TrimSpace(os.Getenv("GENTRAIL_DECIDE_ENDPOINT"))
	apiKey := strings.TrimSpace(os.Getenv("GENTRAIL_API_KEY"))
	if endpoint == "" || apiKey == "" {
		return nil
	}
	return NewEnforcer(endpoint, apiKey)
}

type decideRequest struct {
	EventType    string         `json:"event_type"`
	ToolName     string         `json:"tool_name"`
	ToolArgs     map[string]any `json:"tool_args"`
	AgentID      string         `json:"agent_id,omitempty"`
	InvocationID string         `json:"invocation_id,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
}

// DecideOption attaches optional caller identity to a Decide request. A bare
// call still gets a verdict, only unscoped and unjoinable.
type DecideOption func(*decideRequest)

// WithAgentID scopes agent-targeted and windowed rules to the caller.
func WithAgentID(id string) DecideOption {
	return func(r *decideRequest) { r.AgentID = id }
}

// WithInvocationID (the invocation's OTel trace id when tracing is on) lets
// the backend join the enforcement record to the ingested trace and gives a
// GATE approver context.
func WithInvocationID(id string) DecideOption {
	return func(r *decideRequest) { r.InvocationID = id }
}

// WithRequestID makes the backend's GATE/BLOCK writes idempotent under
// retries.
func WithRequestID(id string) DecideOption {
	return func(r *decideRequest) { r.RequestID = id }
}

// ambientTraceID is the current OpenTelemetry trace id as 32-char hex, "" when
// no span is recording. Unlike the request id this cannot be synthesized: the
// backend joins the enforcement record to the trace by this exact id, and a
// made-up one would resolve to nothing and be refused all the same.
func ambientTraceID(ctx context.Context) string {
	sc := trace.SpanContextFromContext(ctx)
	if !sc.HasTraceID() {
		return ""
	}
	return sc.TraceID().String()
}

func synthesizedRequestID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Decide returns the backend verdict for a proposed tool call. Fails open:
// any transport or backend error returns ALLOW, because a backend outage must
// never break the agent, only forgo enforcement for that call.
func (e *Enforcer) Decide(ctx context.Context, toolName string, toolArgs map[string]any, opts ...DecideOption) Verdict {
	allow := Verdict{Decision: DecisionAllow}
	if e == nil {
		return allow
	}
	if toolArgs == nil {
		toolArgs = map[string]any{}
	}
	payload := decideRequest{EventType: "tool_call", ToolName: toolName, ToolArgs: toolArgs}
	for _, opt := range opts {
		opt(&payload)
	}
	if payload.RequestID == "" {
		// The backend requires a retry identity; a synthesized one is unique
		// so it never dedups a legitimate second call.
		payload.RequestID = synthesizedRequestID()
	}
	if payload.InvocationID == "" {
		payload.InvocationID = ambientTraceID(ctx)
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return allow
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.base+"/api/v1/decide", bytes.NewReader(body))
	if err != nil {
		return allow
	}
	req.Header.Set("Content-Type", "application/json")
	e.setAuthHeaders(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return allow
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return allow
	}
	var verdict Verdict
	if err := json.NewDecoder(resp.Body).Decode(&verdict); err != nil {
		return allow
	}
	return verdict
}

// AwaitGate polls a GATE hold's status resource every ~2s until it resolves,
// returning GateApproved, GateDenied, GateExpired, or GateTimeout. A timeout
// <= 0 uses the enforcer's default. Unlike Decide this fails closed: an
// unreachable, unresolved, or missing hold returns a non-approved status,
// because running a gated action without a confirmed approval is exactly what
// the gate exists to prevent. The backend hold expires independently
// (deny-by-default) at its own expires_at.
func (e *Enforcer) AwaitGate(ctx context.Context, approval *Approval, timeout time.Duration) string {
	if e == nil || approval == nil || approval.StatusURL == "" {
		return GateTimeout
	}
	if timeout <= 0 {
		timeout = e.gateTimeout
	}
	deadline := time.Now().Add(timeout)
	for {
		status, ok := e.pollGate(ctx, e.base+approval.StatusURL)
		if !ok {
			return GateTimeout
		}
		if status != "pending" {
			return status
		}
		if !time.Now().Before(deadline) {
			return GateTimeout
		}
		select {
		case <-ctx.Done():
			return GateTimeout
		case <-time.After(e.pollInterval):
		}
	}
}

func (e *Enforcer) pollGate(ctx context.Context, url string) (status string, ok bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", false
	}
	e.setAuthHeaders(req)
	resp, err := e.client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", false
	}
	var hold struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&hold); err != nil {
		return "", false
	}
	if hold.Status == "" {
		return "pending", true
	}
	return hold.Status, true
}

func (e *Enforcer) setAuthHeaders(req *http.Request) {
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("User-Agent", enforcerUserAgent)
}

// Enforce runs one decide-and-gate cycle for a proposed tool call. ALLOW, an
// unknown decision, and an approved GATE return (true, ""). BLOCK and a
// denied, expired, or unanswered GATE return (false, message), where message
// is what the model should see in place of the tool result. GATE waits up to
// the enforcer's gate timeout. A nil Enforcer allows every call.
func (e *Enforcer) Enforce(ctx context.Context, toolName string, toolArgs map[string]any, opts ...DecideOption) (allowed bool, message string) {
	if e == nil {
		return true, ""
	}
	verdict := e.Decide(ctx, toolName, toolArgs, opts...)
	switch verdict.Decision {
	case DecisionBlock:
		return false, verdictMessage(verdict)
	case DecisionGate:
		status := e.AwaitGate(ctx, verdict.Approval, e.gateTimeout)
		if status == GateApproved {
			return true, ""
		}
		return false, verdictMessage(verdict) + " (approval " + status + ")"
	default:
		return true, ""
	}
}

func verdictMessage(verdict Verdict) string {
	if verdict.Message != "" {
		return verdict.Message
	}
	return strings.TrimSpace(verdict.Decision + " by policy " + verdict.Rule)
}
