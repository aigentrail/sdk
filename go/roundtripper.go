package gentrail

import (
	"fmt"
	"net/http"
	"time"
)

// HTTPRoundTripper wraps base so each request emits a governance model_call
// span with latency and status. Use it on an LLM-specific client for zero-touch
// instrumentation; for model name, prompt, and tokens use RecordModelCall. A
// nil Tracer returns base unchanged.
func (t *Tracer) HTTPRoundTripper(base http.RoundTripper) http.RoundTripper {
	if t == nil {
		return base
	}
	if base == nil {
		base = http.DefaultTransport
	}
	return &governanceRoundTripper{tracer: t, base: base}
}

type governanceRoundTripper struct {
	tracer *Tracer
	base   http.RoundTripper
}

func (rt *governanceRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	startedAt := time.Now()
	resp, err := rt.base.RoundTrip(req)

	status := "ok"
	if err != nil {
		status = "error"
	} else if resp.StatusCode >= 400 {
		status = fmt.Sprintf("http_%d", resp.StatusCode)
	}

	rt.tracer.RecordLLMCall(req.Context(), LLMCallParams{
		ModelID:   req.URL.Host,
		Prompt:    req.Method + " " + req.URL.Path,
		Response:  status,
		LatencyMS: float64(time.Since(startedAt).Milliseconds()),
		Status:    status,
	})
	return resp, err
}
