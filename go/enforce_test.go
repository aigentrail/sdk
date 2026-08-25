package gentrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
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

	for _, k := range []string{"agent_id", "invocation_id", "request_id"} {
		if _, present := gotBody[k]; present {
			t.Errorf("body must omit %q when not given", k)
		}
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
