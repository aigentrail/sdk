package gentrail

import (
	"context"
	"net/http"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type fakeRoundTripper struct{ status int }

func (f fakeRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: f.status, Body: http.NoBody, Header: make(http.Header)}, nil
}

func TestHTTPRoundTripperRecordsModelCall(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	rt := tracer.HTTPRoundTripper(fakeRoundTripper{status: 200})

	req, _ := http.NewRequestWithContext(context.Background(), "POST", "https://api.mistral.ai/v1/chat/completions", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("roundtrip resp=%v err=%v", resp, err)
	}

	var model sdktrace.ReadOnlySpan
	for _, s := range recorder.Ended() {
		if s.Name() == "governance.model_call" {
			model = s
		}
	}
	if model == nil {
		t.Fatal("no governance.model_call span recorded")
	}
	if got := attrMap(model.Attributes())["llm.model_name"].AsString(); got != "api.mistral.ai" {
		t.Errorf("model_name = %q, want request host", got)
	}
}

func TestHTTPRoundTripperNilTracerReturnsBaseUnwrapped(t *testing.T) {
	var tracer *Tracer
	if _, wrapped := tracer.HTTPRoundTripper(fakeRoundTripper{status: 200}).(*governanceRoundTripper); wrapped {
		t.Error("nil tracer must return base unwrapped")
	}
}
