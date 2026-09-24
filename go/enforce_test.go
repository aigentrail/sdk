package gentrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

func newTestEnforcer(url string) *Enforcer {
	e := NewEnforcer(url, "sk-test-key")
	e.pollInterval = time.Millisecond
	return e
}

func TestDecideSendsPayloadIdentityAndHeaders(t *testing.T) {
	var gotPath, gotAuth, gotAgent string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotAgent = r.Header.Get("User-Agent")
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode request body: %v", err)
		}
		json.NewEncoder(w).Encode(Verdict{
			Decision: DecisionBlock,
			Rule:     "destructive_sql_pre",
			Message:  "BLOCKED: destructive SQL on production.",
		})
	}))
	defer srv.Close()

	v := newTestEnforcer(srv.URL).Decide(
		context.Background(),
		"run_sql",
		map[string]any{"database": "production"},
		WithAgentID("agent-reporter"),
		WithInvocationID("0af7651916cd43dd8448eb211c80319c"),
		WithRequestID("tooluse_abc123"),
	)

	if v.Decision != DecisionBlock || v.Rule != "destructive_sql_pre" {
		t.Errorf("verdict = %+v, want BLOCK by destructive_sql_pre", v)
	}
	if gotPath != "/api/v1/decide" {
		t.Errorf("path = %q", gotPath)
	}
	if gotAuth != "Bearer sk-test-key" {
		t.Errorf("authorization = %q", gotAuth)
	}
	if gotAgent != "gentrail-sdk-go" {
		t.Errorf("user-agent = %q", gotAgent)
	}
	want := map[string]any{
		"event_type":    "tool_call",
		"tool_name":     "run_sql",
		"agent_id":      "agent-reporter",
		"invocation_id": "0af7651916cd43dd8448eb211c80319c",
		"request_id":    "tooluse_abc123",
	}
	for k, wv := range want {
		if gotBody[k] != wv {
			t.Errorf("body[%q] = %v, want %v", k, gotBody[k], wv)
		}
	}
	if args, _ := gotBody["tool_args"].(map[string]any); args["database"] != "production" {
		t.Errorf("tool_args = %v", gotBody["tool_args"])
	}
}

func TestDecideOmitsIdentityFieldsWhenAbsent(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(Verdict{Decision: DecisionAllow})
	}))
	defer srv.Close()

	newTestEnforcer(srv.URL).Decide(context.Background(), "run_sql", nil)

	for _, k := range []string{"agent_id", "invocation_id"} {
		if _, present := gotBody[k]; present {
			t.Errorf("body must omit %q when not given", k)
		}
	}
	// The backend requires a retry identity, so a bare call synthesizes one.
	if id, _ := gotBody["request_id"].(string); id == "" {
		t.Error("body must carry a synthesized request_id when none is given")
	}
	if _, present := gotBody["tool_args"]; !present {
		t.Error("tool_args must be present even for a nil args map")
	}
}

func TestDecideFailsOpenWhenUnreachable(t *testing.T) {
	v := newTestEnforcer("http://127.0.0.1:1").Decide(context.Background(), "run_sql", nil)
	if v.Decision != DecisionAllow {
		t.Errorf("decision = %q, want ALLOW on transport error", v.Decision)
	}
}

func TestDecideFailsOpenOnBackendError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer srv.Close()

	v := newTestEnforcer(srv.URL).Decide(context.Background(), "run_sql", nil)
	if v.Decision != DecisionAllow {
		t.Errorf("decision = %q, want ALLOW on backend error", v.Decision)
	}
}

func TestAwaitGateApprovedAfterPending(t *testing.T) {
	var polls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/approvals/x" {
			t.Errorf("poll path = %q", r.URL.Path)
		}
		status := "pending"
		if polls.Add(1) >= 3 {
			status = "approved"
		}
		json.NewEncoder(w).Encode(map[string]string{"status": status})
	}))
	defer srv.Close()

	got := newTestEnforcer(srv.URL).AwaitGate(
		context.Background(), &Approval{StatusURL: "/api/v1/approvals/x"}, time.Second,
	)
	if got != GateApproved {
		t.Errorf("status = %q, want approved", got)
	}
	if polls.Load() < 3 {
		t.Errorf("polls = %d, want at least 3", polls.Load())
	}
}

func TestAwaitGateReturnsDenied(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "denied"})
	}))
	defer srv.Close()

	got := newTestEnforcer(srv.URL).AwaitGate(context.Background(), &Approval{StatusURL: "/x"}, time.Second)
	if got != GateDenied {
		t.Errorf("status = %q, want denied", got)
	}
}

func TestAwaitGateFailsClosedOnTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}))
	defer srv.Close()

	got := newTestEnforcer(srv.URL).AwaitGate(context.Background(), &Approval{StatusURL: "/x"}, 20*time.Millisecond)
	if got != GateTimeout {
		t.Errorf("status = %q, want timeout on an unanswered gate", got)
	}
}

func TestAwaitGateFailsClosedWithoutStatusURL(t *testing.T) {
	e := newTestEnforcer("http://127.0.0.1:1")
	if got := e.AwaitGate(context.Background(), nil, time.Second); got != GateTimeout {
		t.Errorf("nil approval: status = %q, want timeout", got)
	}
	if got := e.AwaitGate(context.Background(), &Approval{}, time.Second); got != GateTimeout {
		t.Errorf("empty status_url: status = %q, want timeout", got)
	}
}

func TestAwaitGateFailsClosedWhenUnreachable(t *testing.T) {
	got := newTestEnforcer("http://127.0.0.1:1").AwaitGate(context.Background(), &Approval{StatusURL: "/x"}, time.Second)
	if got != GateTimeout {
		t.Errorf("status = %q, want timeout when the backend is unreachable", got)
	}
}

func TestNilEnforcerAllowsAndFailsClosedOnGate(t *testing.T) {
	var e *Enforcer
	if v := e.Decide(context.Background(), "run_sql", nil); v.Decision != DecisionAllow {
		t.Errorf("nil enforcer decision = %q, want ALLOW", v.Decision)
	}
	if got := e.AwaitGate(context.Background(), &Approval{StatusURL: "/x"}, time.Second); got != GateTimeout {
		t.Errorf("nil enforcer gate = %q, want timeout", got)
	}
}

func TestNewEnforcerFromEnv(t *testing.T) {
	t.Setenv("GENTRAIL_DECIDE_ENDPOINT", "")
	t.Setenv("GENTRAIL_API_KEY", "")
	if NewEnforcerFromEnv() != nil {
		t.Error("must be nil with no env")
	}
	t.Setenv("GENTRAIL_DECIDE_ENDPOINT", "https://example.test/")
	if NewEnforcerFromEnv() != nil {
		t.Error("must be nil without an api key")
	}
	t.Setenv("GENTRAIL_API_KEY", "sk")
	e := NewEnforcerFromEnv()
	if e == nil {
		t.Fatal("must build with both env vars set")
	}
	if e.base != "https://example.test" {
		t.Errorf("base = %q, want trailing slash trimmed", e.base)
	}
}

func TestGateTimeoutSecondsEnvOverride(t *testing.T) {
	t.Setenv("GENTRAIL_GATE_TIMEOUT_SECONDS", "1.5")
	e := NewEnforcer("https://example.test", "sk")
	if e.gateTimeout != 1500*time.Millisecond {
		t.Errorf("gateTimeout = %v, want 1.5s", e.gateTimeout)
	}
}

// The backend refuses a BLOCK/GATE record it cannot join to a trace, so a
// caller already inside a recording span should not have to pass the id by
// hand. It cannot be synthesized: only the real trace id resolves.
func TestDecideFallsBackToTheAmbientTraceID(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(Verdict{Decision: DecisionAllow})
	}))
	defer srv.Close()

	traceID, _ := trace.TraceIDFromHex("0af7651916cd43dd8448eb211c80319c")
	spanID, _ := trace.SpanIDFromHex("b7ad6b7169203331")
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID,
	}))

	newTestEnforcer(srv.URL).Decide(ctx, "run_sql", nil)

	if got := gotBody["invocation_id"]; got != "0af7651916cd43dd8448eb211c80319c" {
		t.Errorf("invocation_id = %v, want the ambient trace id", got)
	}
}

func TestDecideExplicitInvocationIDBeatsTheAmbientOne(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&gotBody)
		json.NewEncoder(w).Encode(Verdict{Decision: DecisionAllow})
	}))
	defer srv.Close()

	traceID, _ := trace.TraceIDFromHex("0af7651916cd43dd8448eb211c80319c")
	spanID, _ := trace.SpanIDFromHex("b7ad6b7169203331")
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID,
	}))

	newTestEnforcer(srv.URL).Decide(ctx, "run_sql", nil,
		WithInvocationID("4bf92f3577b34da6a3ce929d0e0e4736"))

	if got := gotBody["invocation_id"]; got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Errorf("invocation_id = %v, want the explicit id", got)
	}
}

type enforceVector struct {
	Name       string          `json:"name"`
	Verdict    json.RawMessage `json:"verdict"`
	GateStatus *string         `json:"gate_status"`
	Allowed    bool            `json:"allowed"`
	Message    string          `json:"message"`
}

func loadEnforceVectors(t *testing.T) []enforceVector {
	t.Helper()
	raw, err := os.ReadFile("../spec/enforce_vectors.json")
	if err != nil {
		t.Fatalf("read enforce vectors: %v", err)
	}
	var vectors []enforceVector
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("unmarshal enforce vectors: %v", err)
	}
	if len(vectors) == 0 {
		t.Fatal("no enforce vectors")
	}
	return vectors
}

func newEnforceVectorServer(t *testing.T, vector enforceVector) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/decide":
			w.Write(vector.Verdict)
		case "/api/v1/approvals/1":
			if vector.GateStatus == nil {
				t.Errorf("gate polled although the vector has no gate status")
				http.Error(w, "unexpected poll", http.StatusInternalServerError)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"status": *vector.GateStatus})
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
			http.NotFound(w, r)
		}
	}))
}

func TestEnforceMatchesSharedVectors(t *testing.T) {
	for _, vector := range loadEnforceVectors(t) {
		t.Run(vector.Name, func(t *testing.T) {
			srv := newEnforceVectorServer(t, vector)
			defer srv.Close()
			enforcer := newTestEnforcer(srv.URL)
			enforcer.gateTimeout = time.Second

			allowed, message := enforcer.Enforce(context.Background(), "wire_funds", map[string]any{"amount": 10},
				WithAgentID("agent-1"), WithRequestID("req-1"))

			if allowed != vector.Allowed || message != vector.Message {
				t.Errorf("Enforce = (%v, %q), want (%v, %q)", allowed, message, vector.Allowed, vector.Message)
			}
		})
	}
}

func TestEnforceGateWaitsForTheConfiguredTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/decide" {
			json.NewEncoder(w).Encode(Verdict{Decision: DecisionGate, Rule: "r", Approval: &Approval{StatusURL: "/hold"}})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"status": "pending"})
	}))
	defer srv.Close()
	enforcer := newTestEnforcer(srv.URL)
	enforcer.gateTimeout = 20 * time.Millisecond

	allowed, message := enforcer.Enforce(context.Background(), "t", nil)

	if allowed || message != "GATE by policy r (approval timeout)" {
		t.Errorf("Enforce = (%v, %q), want an unanswered gate to fail closed", allowed, message)
	}
}

func TestNilEnforcerEnforceAllows(t *testing.T) {
	var e *Enforcer
	if allowed, message := e.Enforce(context.Background(), "run_sql", nil); !allowed || message != "" {
		t.Errorf("nil Enforce = (%v, %q), want (true, \"\")", allowed, message)
	}
}
