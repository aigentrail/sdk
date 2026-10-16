package admission

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdmissionRequiresConfirmedUnexpiredConsumption(t *testing.T) {
	for _, test := range []struct {
		name    string
		change  func(*admissionReceipt)
		allowed bool
	}{
		{"confirmed", func(*admissionReceipt) {}, true},
		{"replayed", func(r *admissionReceipt) { r.ExecutionAuthorized = false }, false},
		{"expired", func(r *admissionReceipt) { r.Reservation.ExpiresAt = 100 }, false},
		{"foreign request", func(r *admissionReceipt) { r.Reservation.RequestID = "other" }, false},
		{"revision changed", func(r *admissionReceipt) { r.Reservation.RevisionID = "other" }, false},
		{"window changed", func(r *admissionReceipt) { r.Reservation.WindowEnd++ }, false},
		{"unknown outcome", func(r *admissionReceipt) { r.Outcome = "unknown" }, false},
		{"not consumed", func(r *admissionReceipt) { r.Reservation.State = "reserved" }, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get("Authorization") != "Bearer key" || r.Method != http.MethodPost {
					t.Error("missing authenticated POST")
				}
				var body map[string]string
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body["proposal_hash"] != strings.Repeat("a", 64) {
					t.Error("proposal binding lost")
				}
				receipt := admissionReceipt{Outcome: "verified", ConsumeURL: "/consume", Reservation: admissionReservation{RequestID: "call", State: "reserved", ExpiresAt: 120, WindowStart: 60, WindowEnd: 180, RevisionID: "revision"}}
				if r.URL.Path == "/consume" {
					receipt.Reservation.State = "consumed"
					receipt.ExecutionAuthorized = true
					test.change(&receipt)
				}
				if err := json.NewEncoder(w).Encode(receipt); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			client := Client{DecideEndpoint: server.URL + "/api/v1/decide", APIKey: "key", HTTP: server.Client(), Now: func() time.Time { return time.Unix(100, 0) }}
			err := client.Authorize(context.Background(), "call", Link{Required: true, Protocol: Protocol, ProposalHash: strings.Repeat("a", 64), ReserveURL: "/reserve"})
			if (err == nil) != test.allowed || calls != 2 {
				t.Fatalf("allowed=%v calls=%d error=%v", test.allowed, calls, err)
			}
		})
	}
}

func TestAdmissionRejectsMalformedTransportAndNeverRetries(t *testing.T) {
	for _, response := range []string{"{}", "null", `{"execution_authorized":true}`, `{"outcome":"verified","execution_authorized":"true"}`, strings.Repeat("x", 65537)} {
		calls := 0
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls++; _, _ = io.WriteString(w, response) }))
		client := Client{DecideEndpoint: server.URL, HTTP: server.Client(), Now: time.Now}
		err := client.Authorize(context.Background(), "call", Link{Required: true, Protocol: Protocol, ProposalHash: strings.Repeat("a", 64), ReserveURL: "/reserve"})
		server.Close()
		if err == nil || calls != 1 {
			t.Fatalf("malformed response allowed or retried: %d %v", calls, err)
		}
	}
}

func TestAdmissionDoesNotLeakCredentialsThroughLinksOrRedirects(t *testing.T) {
	foreignCalls := 0
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreignCalls++ }))
	defer foreign.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	client := Client{DecideEndpoint: server.URL, APIKey: "secret", HTTP: server.Client(), Now: time.Now}
	for _, link := range []string{foreign.URL, "/redirect"} {
		if err := client.Authorize(context.Background(), "call", Link{Required: true, Protocol: Protocol, ProposalHash: strings.Repeat("a", 64), ReserveURL: link}); err == nil {
			t.Fatal("foreign link allowed")
		}
	}
	if foreignCalls != 0 {
		t.Fatal("credentials sent to foreign server")
	}
}

func TestAdmissionLostConsumeReplyNeverRetriesOrGrantsExecution(t *testing.T) {
	var consumes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/consume" {
			consumes.Add(1)
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			if err := connection.Close(); err != nil {
				t.Error(err)
			}
			return
		}
		receipt := admissionReceipt{Outcome: "verified", ConsumeURL: "/consume", Reservation: admissionReservation{RequestID: "call", State: "reserved", ExpiresAt: 120, WindowStart: 60, WindowEnd: 180, RevisionID: "revision"}}
		if err := json.NewEncoder(w).Encode(receipt); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	client := Client{DecideEndpoint: server.URL, HTTP: server.Client(), Now: func() time.Time { return time.Unix(100, 0) }}
	if err := client.Authorize(context.Background(), "call", Link{Required: true, Protocol: Protocol, ProposalHash: strings.Repeat("a", 64), ReserveURL: "/reserve"}); err == nil {
		t.Fatal("lost reply granted execution")
	}
	if consumes.Load() != 1 {
		t.Fatalf("consume retried %d times", consumes.Load())
	}
}
