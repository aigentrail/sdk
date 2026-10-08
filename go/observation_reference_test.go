package gentrail

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestObservationArgumentsMatchPortableVectors(t *testing.T) {
	raw, err := os.ReadFile("../spec/observation_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Arguments string
		Canonical string
		SHA256    string
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		digest, err := observationArgumentsHash(vector.Arguments)
		if err != nil || digest != vector.SHA256 {
			t.Fatalf("%s: digest=%s err=%v", vector.Arguments, digest, err)
		}
	}
}

func TestDecideReturnsOnlyMatchingObservationReferenceWithoutChangingVerdict(t *testing.T) {
	digest, err := observationArgumentsHash(`{"amount":1}`)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range []string{"matching", "wrong-request", "wrong-invocation", "wrong-arguments", "invalid-proposal", "unavailable"} {
		t.Run(scenario, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var request decideRequest
				if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
					t.Error(err)
					w.WriteHeader(400)
					return
				}
				reference := &DecisionReference{RequestID: request.RequestID, InvocationID: request.InvocationID, ProposalHash: strings.Repeat("a", 64), ArgumentsHash: digest}
				outcome := "verified"
				switch scenario {
				case "wrong-request":
					reference.RequestID = "other"
				case "wrong-invocation":
					reference.InvocationID = "other"
				case "wrong-arguments":
					reference.ArgumentsHash = strings.Repeat("b", 64)
				case "invalid-proposal":
					reference.ProposalHash = "bad"
				case "unavailable":
					outcome = "unavailable"
				}
				if err := json.NewEncoder(w).Encode(Verdict{Decision: DecisionBlock, Outcome: outcome, Reference: reference, ObservationsURL: "/api/v1/decisions/request/observations"}); err != nil {
					t.Error(err)
				}
			}))
			defer server.Close()
			verdict := newTestEnforcer(server.URL).Decide(context.Background(), "pay", map[string]any{"amount": 1}, WithAgentID("agent"), WithInvocationID("check"), WithRequestID("request"))
			if verdict.Decision != DecisionBlock {
				t.Fatal("receipt validation changed permission")
			}
			if (verdict.Reference != nil) != (scenario == "matching") {
				t.Fatalf("scenario=%s reference=%+v", scenario, verdict.Reference)
			}
		})
	}
}

func TestRecordToolCallHashesActualArgumentsBeforeTruncation(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "agent"})
	proposedHash, err := observationArgumentsHash(`{"value":"proposed"}`)
	if err != nil {
		t.Fatal(err)
	}
	reference := &DecisionReference{RequestID: "request", InvocationID: "original-check", ProposalHash: strings.Repeat("a", 64), ArgumentsHash: proposedHash}
	arguments := `{"value":"` + strings.Repeat("x", maxInputValueRunes+100) + `"}`
	actualHash, err := observationArgumentsHash(arguments)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracer.RecordToolCall(ctx, ToolCallParams{Name: "pay", AgentID: "agent", Args: arguments, DecisionReference: reference}); err != nil {
		t.Fatal(err)
	}
	inv.End(InvocationEndParams{})
	for _, span := range recorder.Ended() {
		if span.Name() != "pay" {
			continue
		}
		attrs := attrMap(span.Attributes())
		if attrs["aigentrail.decision.arguments_hash"].AsString() != actualHash || actualHash == proposedHash || reference.ArgumentsHash != proposedHash {
			t.Fatal("observed arguments reused proposed digest")
		}
		if attrs["aigentrail.decision.invocation_id"].AsString() != "original-check" || attrs["aigentrail.decision.request_id"].AsString() != "request" {
			t.Fatal("decision identity lost")
		}
		if len(attrs["input.value"].AsString()) >= len(arguments) {
			t.Fatal("hash proof did not exercise truncated arguments")
		}
		return
	}
	t.Fatal("tool span missing")
}

func TestRecordToolCallRejectsInvalidReferenceWithoutFabricatingLink(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	if err := tracer.RecordToolCall(context.Background(), ToolCallParams{Name: "pay", Args: "{}", DecisionReference: &DecisionReference{RequestID: "request"}}); err == nil {
		t.Fatal("invalid reference accepted")
	}
	for _, span := range recorder.Ended() {
		if _, exists := attrMap(span.Attributes())["aigentrail.decision.request_id"]; exists {
			t.Fatal("invalid reference exported as linked")
		}
	}
}
