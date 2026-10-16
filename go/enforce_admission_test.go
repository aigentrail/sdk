package gentrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aigentrail/sdk/go/admission"
)

func TestStrictEnforcementApprovesThenConsumesOnlyOnce(t *testing.T) {
	for _, gate := range []bool{false, true} {
		fixture := &quotaEnforcerServer{t: t, gate: gate}
		server := httptest.NewServer(http.HandlerFunc(fixture.serveHTTP))
		e := NewEnforcer(server.URL, "key", WithStrictAdmission())
		e.now = func() time.Time { return time.Unix(100, 0) }
		for _, want := range []bool{true, false} {
			allowed, message := e.Enforce(context.Background(), "Read", nil, WithRequestID("call"))
			if allowed != want {
				t.Fatalf("allowed=%v want=%v message=%s", allowed, want, message)
			}
		}
		server.Close()
		fixture.mu.Lock()
		wantPaths := []string{"/api/v1/decide", "/reserve", "/consume", "/api/v1/decide", "/reserve", "/consume"}
		if gate {
			wantPaths = []string{"/api/v1/decide", "/approval", "/reserve", "/consume", "/api/v1/decide", "/approval", "/reserve", "/consume"}
		}
		if !reflect.DeepEqual(fixture.paths, wantPaths) {
			t.Errorf("transition order=%v", fixture.paths)
		}
		fixture.mu.Unlock()
	}
}

func TestStrictEnforcerFailsClosedBeforeAndAfterDecision(t *testing.T) {
	for _, raw := range []string{`broken`, `{"decision":"ALLOW"}`, `{"decision":"ALLOW","outcome":"unknown"}`, `{"decision":"ALLOW","outcome":"verified","admission":null}`, `{"decision":"ALLOW","outcome":"verified","admission":false}`, `{"decision":"ALLOW","outcome":"verified","admission":{}}`} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(raw)) }))
		e := NewEnforcer(server.URL, "key", WithStrictAdmission())
		if allowed, _ := e.Enforce(context.Background(), "Read", nil); allowed {
			t.Errorf("malformed response allowed: %s", raw)
		}
		server.Close()
	}
	e := NewEnforcer("http://127.0.0.1:1", "key", WithStrictAdmission())
	if allowed, _ := e.Enforce(context.Background(), "Read", nil); allowed {
		t.Fatal("outage allowed strict execution")
	}
}

type quotaEnforcerServer struct {
	t        *testing.T
	mu       sync.Mutex
	paths    []string
	consumes int
	gate     bool
}

func (fixture *quotaEnforcerServer) serveHTTP(w http.ResponseWriter, r *http.Request) {
	fixture.mu.Lock()
	defer fixture.mu.Unlock()
	fixture.paths = append(fixture.paths, r.URL.Path)
	switch r.URL.Path {
	case "/api/v1/decide":
		var request decideRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			fixture.t.Error(err)
		}
		if request.AdmissionProtocol != admission.Protocol || request.RequestID != "call" {
			fixture.t.Error("missing admission capability or retry identity")
		}
		verdict := Verdict{Decision: DecisionAllow, Outcome: "verified", Admission: &admission.Link{Required: true, Protocol: admission.Protocol, ProposalHash: strings.Repeat("a", 64), ReserveURL: "/reserve"}}
		if fixture.gate {
			verdict.Decision = DecisionGate
			verdict.Approval = &Approval{StatusURL: "/approval"}
		}
		if err := json.NewEncoder(w).Encode(verdict); err != nil {
			fixture.t.Error(err)
		}
	case "/approval":
		if err := json.NewEncoder(w).Encode(map[string]string{"status": "approved"}); err != nil {
			fixture.t.Error(err)
		}
	case "/reserve", "/consume":
		state := "reserved"
		authorized := false
		if r.URL.Path == "/consume" {
			fixture.consumes++
			state = "consumed"
			authorized = fixture.consumes == 1
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"outcome": "verified", "execution_authorized": authorized, "consume_url": "/consume", "reservation": map[string]any{"request_id": "call", "state": state, "expires_at": 120, "window_start": 60, "window_end": 180, "revision_id": "revision"}}); err != nil {
			fixture.t.Error(err)
		}
	default:
		fixture.t.Error("unexpected request", r.URL.Path)
	}
}
