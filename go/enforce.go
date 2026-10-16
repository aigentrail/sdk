package gentrail

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aigentrail/sdk/go/admission"
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
	Admission       *admission.Link `json:"admission,omitempty"`
	requestID       string
	Outcome         string             `json:"outcome,omitempty"`
	Reference       *DecisionReference `json:"observation_reference,omitempty"`
	ObservationsURL string             `json:"observations_url,omitempty"`
	Decision        string             `json:"decision"`
	Rule            string             `json:"rule,omitempty"`
	Message         string             `json:"message,omitempty"`
	Approval        *Approval          `json:"approval,omitempty"`
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
	strictAdmission bool
	now             func() time.Time
	base            string
	apiKey          string
	client          *http.Client
	gateTimeout     time.Duration
	pollInterval    time.Duration
}

type EnforcerOption func(*Enforcer)

func WithStrictAdmission() EnforcerOption {
	return func(e *Enforcer) { e.strictAdmission = true }
}

func NewEnforcer(endpoint, apiKey string, options ...EnforcerOption) *Enforcer {
	gateTimeout := defaultGateTimeout
	if v := os.Getenv("GENTRAIL_GATE_TIMEOUT_SECONDS"); v != "" {
		if secs, err := strconv.ParseFloat(v, 64); err == nil && secs > 0 {
			gateTimeout = time.Duration(secs * float64(time.Second))
		}
	}
	enforcer := &Enforcer{
		now:          time.Now,
		base:         strings.TrimRight(endpoint, "/"),
		apiKey:       apiKey,
		client:       &http.Client{Timeout: defaultDecideTimeout, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		gateTimeout:  gateTimeout,
		pollInterval: defaultGatePollInterval,
	}
	for _, option := range options {
		option(enforcer)
	}
	return enforcer
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
	AdmissionProtocol string         `json:"admission_protocol,omitempty"`
	EventType         string         `json:"event_type"`
	ToolName          string         `json:"tool_name"`
	ToolArgs          map[string]any `json:"tool_args"`
	AgentID           string         `json:"agent_id,omitempty"`
	InvocationID      string         `json:"invocation_id,omitempty"`
	RequestID         string         `json:"request_id,omitempty"`
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

func (e *Enforcer) Decide(ctx context.Context, toolName string, toolArgs map[string]any, opts ...DecideOption) Verdict {
	allow := Verdict{Decision: DecisionAllow, Outcome: "unavailable"}
	if e == nil {
		return allow
	}
	if e.strictAdmission {
		allow.Decision = DecisionBlock
		allow.Message = "Gentrail could not verify this tool-call attempt; the call was not run."
	}
	if toolArgs == nil {
		toolArgs = map[string]any{}
	}
	payload := decideRequest{EventType: "tool_call", ToolName: toolName, ToolArgs: toolArgs}
	if e.strictAdmission {
		payload.AdmissionProtocol = admission.Protocol
	}
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
	verdict := e.decidePayload(ctx, payload, allow)

	switch verdict.Outcome {
	case "verified", "request_conflict":
	default:
		verdict.Outcome = "unavailable"
	}
	switch verdict.Decision {
	case DecisionAllow, DecisionBlock, DecisionGate:
	default:
		verdict.Outcome = "unavailable"
	}
	verdict.validateObservationReference(payload)
	verdict.requestID = payload.RequestID
	if e.strictAdmission && verdict.Outcome != "verified" {
		verdict.Decision = DecisionBlock
	}
	return verdict
}

func (e *Enforcer) decidePayload(ctx context.Context, payload decideRequest, allow Verdict) Verdict {
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
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024+1))
	if err != nil || len(raw) > 2*1024*1024 {
		return allow
	}
	verdict, err := decodeVerdict(raw)
	if err != nil {
		return allow
	}
	return verdict
}

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
			return e.authorizeAdmission(ctx, verdict)
		}
		return false, verdictMessage(verdict) + " (approval " + status + ")"
	default:
		return e.authorizeAdmission(ctx, verdict)
	}
}

func verdictMessage(verdict Verdict) string {
	if verdict.Message != "" {
		return verdict.Message
	}
	return strings.TrimSpace(verdict.Decision + " by policy " + verdict.Rule)
}

func decodeVerdict(raw []byte) (Verdict, error) {
	var wire struct {
		Decision        string          `json:"decision"`
		Outcome         json.RawMessage `json:"outcome"`
		Rule            json.RawMessage `json:"rule"`
		Message         json.RawMessage `json:"message"`
		Approval        json.RawMessage `json:"approval"`
		Reference       json.RawMessage `json:"observation_reference"`
		ObservationsURL json.RawMessage `json:"observations_url"`
		Admission       json.RawMessage `json:"admission"`
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		return Verdict{}, err
	}
	verdict := Verdict{Decision: wire.Decision, Outcome: verdictText(wire.Outcome), Rule: verdictText(wire.Rule), Message: verdictText(wire.Message), ObservationsURL: verdictText(wire.ObservationsURL)}
	if len(wire.Admission) != 0 {
		verdict.Admission = &admission.Link{}
		if err := json.Unmarshal(wire.Admission, verdict.Admission); err != nil {
			verdict.Decision = DecisionBlock
			verdict.Message = "Gentrail returned invalid execution admission; the call was not run."
		}
	}
	var reference DecisionReference
	if err := json.Unmarshal(wire.Reference, &reference); err == nil {
		verdict.Reference = &reference
	}
	var approval Approval
	if err := json.Unmarshal(wire.Approval, &approval); err == nil {
		verdict.Approval = &approval
	}
	return verdict, nil
}

func verdictText(raw json.RawMessage) string {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return ""
	}
	return text
}
