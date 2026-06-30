package gentrail

import (
	"context"
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func newTestTracer(t *testing.T) (*Tracer, *tracetest.SpanRecorder) {
	t.Helper()
	recorder := tracetest.NewSpanRecorder()
	provider := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	return &Tracer{
		tracer:   provider.Tracer("aigentrail.test"),
		provider: provider,
	}, recorder
}

func attrMap(attrs []attribute.KeyValue) map[string]attribute.Value {
	m := make(map[string]attribute.Value, len(attrs))
	for _, kv := range attrs {
		m[string(kv.Key)] = kv.Value
	}
	return m
}

func TestStartInvocationSetsAllAttributes(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	_, inv := tracer.StartInvocation(context.Background(), InvocationParams{
		AgentID:     "agent-1",
		AgentName:   "Classifier",
		JournalID:   "journal-xyz",
		UserMessage: "classify these tools",
	})
	inv.End(InvocationEndParams{
		Response:      "done",
		TotalTokens:   42,
		ToolCount:     3,
		IntegrityHash: "abc123",
	})

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("want 1 span, got %d", len(spans))
	}
	span := spans[0]
	if span.Name() != "governance.invocation" {
		t.Errorf("name = %q, want governance.invocation", span.Name())
	}
	attrs := attrMap(span.Attributes())
	checks := map[string]attribute.Value{
		"openinference.span.kind":           attribute.StringValue("AGENT"),
		"aigentrail.agent.id":               attribute.StringValue("agent-1"),
		"agent.name":                        attribute.StringValue("Classifier"),
		"aigentrail.journal.id":             attribute.StringValue("journal-xyz"),
		"session.id":                        attribute.StringValue("journal-xyz"),
		"input.value":                       attribute.StringValue("classify these tools"),
		"source":                            attribute.StringValue("aigentrail-sdk"),
		"output.value":                      attribute.StringValue("done"),
		"aigentrail.invocation.status":      attribute.StringValue("ok"),
		"aigentrail.journal.integrity_hash": attribute.StringValue("abc123"),
		"llm.token_count.total":             attribute.Int64Value(42),
		"aigentrail.tool.count":             attribute.Int64Value(3),
	}
	for k, want := range checks {
		got, ok := attrs[k]
		if !ok {
			t.Errorf("missing attribute %q", k)
			continue
		}
		if got.Emit() != want.Emit() {
			t.Errorf("attr %q = %v, want %v", k, got.Emit(), want.Emit())
		}
	}
}

func TestEndInvocationDefaultsStatusToOK(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	_, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	inv.End(InvocationEndParams{})

	attrs := attrMap(recorder.Ended()[0].Attributes())
	if attrs["aigentrail.invocation.status"].AsString() != "ok" {
		t.Errorf("status default = %q, want ok", attrs["aigentrail.invocation.status"].AsString())
	}
}

func TestEndInvocationCustomStatus(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	_, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	inv.End(InvocationEndParams{Status: "blocked"})

	attrs := attrMap(recorder.Ended()[0].Attributes())
	if attrs["aigentrail.invocation.status"].AsString() != "blocked" {
		t.Errorf("status = %q, want blocked", attrs["aigentrail.invocation.status"].AsString())
	}
}

func TestRecordModelCallEmitsLLMSpan(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	tracer.RecordModelCall(ctx, ModelCallParams{
		ModelID:      "mistral-small-latest",
		Prompt:       "hello",
		ResponseText: "hi",
		InputTokens:  10,
		OutputTokens: 5,
		LatencyMS:    123.4,
	})
	inv.End(InvocationEndParams{})

	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("want 2 spans, got %d", len(spans))
	}
	var model sdktrace.ReadOnlySpan
	for _, s := range spans {
		if s.Name() == "governance.model_call" {
			model = s
		}
	}
	if model == nil {
		t.Fatal("no governance.model_call span recorded")
	}
	attrs := attrMap(model.Attributes())
	if attrs["openinference.span.kind"].AsString() != "LLM" {
		t.Errorf("span.kind = %q, want LLM", attrs["openinference.span.kind"].AsString())
	}
	if attrs["llm.model_name"].AsString() != "mistral-small-latest" {
		t.Errorf("model_name = %q", attrs["llm.model_name"].AsString())
	}
	if attrs["llm.token_count.prompt"].AsInt64() != 10 {
		t.Errorf("prompt tokens = %d", attrs["llm.token_count.prompt"].AsInt64())
	}
	if attrs["llm.token_count.completion"].AsInt64() != 5 {
		t.Errorf("completion tokens = %d", attrs["llm.token_count.completion"].AsInt64())
	}
	if attrs["aigentrail.latency_ms"].AsFloat64() != 123.4 {
		t.Errorf("latency = %v", attrs["aigentrail.latency_ms"].AsFloat64())
	}
}

func TestRecordModelCallSkipsZeroLatency(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	tracer.RecordModelCall(ctx, ModelCallParams{ModelID: "m"})
	inv.End(InvocationEndParams{})

	for _, s := range recorder.Ended() {
		if s.Name() != "governance.model_call" {
			continue
		}
		for _, kv := range s.Attributes() {
			if string(kv.Key) == "aigentrail.latency_ms" {
				t.Errorf("latency attr present when LatencyMS==0")
			}
		}
	}
}

func TestRecordToolCallNamesSpanAfterTool(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	tracer.RecordToolCall(ctx, ToolCallParams{
		AgentID:    "a",
		AgentName:  "Agent",
		Name:       "search_web",
		Args:       `{"q":"hi"}`,
		Result:     "ok",
		DurationMS: 7.5,
	})
	inv.End(InvocationEndParams{})

	var tool sdktrace.ReadOnlySpan
	for _, s := range recorder.Ended() {
		if s.Name() == "search_web" {
			tool = s
		}
	}
	if tool == nil {
		t.Fatal("no tool-named span recorded")
	}
	attrs := attrMap(tool.Attributes())
	if attrs["openinference.span.kind"].AsString() != "TOOL" {
		t.Errorf("span.kind = %q", attrs["openinference.span.kind"].AsString())
	}
	if attrs["tool.name"].AsString() != "search_web" {
		t.Errorf("tool.name = %q", attrs["tool.name"].AsString())
	}
	if attrs["aigentrail.agent.id"].AsString() != "a" {
		t.Errorf("agent.id = %q", attrs["aigentrail.agent.id"].AsString())
	}
	if attrs["aigentrail.latency_ms"].AsFloat64() != 7.5 {
		t.Errorf("latency = %v", attrs["aigentrail.latency_ms"].AsFloat64())
	}
}

func TestChildSpansNestUnderInvocation(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	tracer.RecordModelCall(ctx, ModelCallParams{ModelID: "m"})
	tracer.RecordToolCall(ctx, ToolCallParams{Name: "t"})
	inv.End(InvocationEndParams{})

	var invSpanID string
	for _, s := range recorder.Ended() {
		if s.Name() == "governance.invocation" {
			invSpanID = s.SpanContext().SpanID().String()
		}
	}
	if invSpanID == "" {
		t.Fatal("invocation span not recorded")
	}
	for _, s := range recorder.Ended() {
		if s.Name() == "governance.invocation" {
			continue
		}
		if s.Parent().SpanID().String() != invSpanID {
			t.Errorf("span %q parent = %s, want %s", s.Name(), s.Parent().SpanID(), invSpanID)
		}
	}
}

func TestTruncateRunesRespectsCodePoints(t *testing.T) {
	long := strings.Repeat("a", 600)
	if got := truncateRunes(long, 500); len(got) != 500 {
		t.Errorf("truncated len = %d, want 500", len(got))
	}
	multibyte := strings.Repeat("世", 600)
	got := truncateRunes(multibyte, 500)
	if runes := []rune(got); len(runes) != 500 {
		t.Errorf("multibyte rune count = %d, want 500", len(runes))
	}
	if short := truncateRunes("hi", 500); short != "hi" {
		t.Errorf("short string mangled: %q", short)
	}
}

func TestStartInvocationTruncatesLongUserMessage(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	long := strings.Repeat("x", maxInputValueRunes+100)
	_, inv := tracer.StartInvocation(context.Background(), InvocationParams{
		AgentID:     "a",
		UserMessage: long,
	})
	inv.End(InvocationEndParams{})

	attrs := attrMap(recorder.Ended()[0].Attributes())
	if got := attrs["input.value"].AsString(); len(got) != maxInputValueRunes {
		t.Errorf("input.value len = %d, want %d", len(got), maxInputValueRunes)
	}
}

func TestRecordModelCallTruncatesLongOutput(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	long := strings.Repeat("y", maxModelOutputRunes+100)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	tracer.RecordModelCall(ctx, ModelCallParams{ModelID: "m", ResponseText: long})
	inv.End(InvocationEndParams{})

	for _, s := range recorder.Ended() {
		if s.Name() != "governance.model_call" {
			continue
		}
		attrs := attrMap(s.Attributes())
		if got := attrs["output.value"].AsString(); len(got) != maxModelOutputRunes {
			t.Errorf("output.value len = %d, want %d", len(got), maxModelOutputRunes)
		}
	}
}

func TestSplitEndpointVariants(t *testing.T) {
	cases := []struct {
		in       string
		wantHost string
		wantPath string
	}{
		{"https://otel.gentrail.ai:4318", "otel.gentrail.ai:4318", "/v1/traces"},
		{"http://localhost:4318/", "localhost:4318", "/v1/traces"},
		{"https://otel.gentrail.ai:4318/custom", "otel.gentrail.ai:4318", "/custom/v1/traces"},
		{"host:4318", "host:4318", "/v1/traces"},
		{"https://otel.gentrail.ai", "otel.gentrail.ai:443", "/v1/traces"},
		{"http://localhost", "localhost:80", "/v1/traces"},
	}
	for _, c := range cases {
		host, path, err := splitEndpoint(c.in)
		if err != nil {
			t.Errorf("%q: %v", c.in, err)
			continue
		}
		if host != c.wantHost || path != c.wantPath {
			t.Errorf("%q: host=%q path=%q, want host=%q path=%q", c.in, host, path, c.wantHost, c.wantPath)
		}
	}
}

func TestSplitEndpointRejectsEmpty(t *testing.T) {
	if _, _, err := splitEndpoint(""); err == nil {
		t.Error("want error for empty endpoint")
	}
}

func TestNilTracerMethodsAreNoop(t *testing.T) {
	var tracer *Tracer
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	tracer.RecordModelCall(ctx, ModelCallParams{ModelID: "m"})
	tracer.RecordToolCall(ctx, ToolCallParams{Name: "t"})
	tracer.RecordLLMCall(ctx, LLMCallParams{ModelID: "m"})
	inv.End(InvocationEndParams{})
	if err := tracer.ForceFlush(context.Background()); err != nil {
		t.Errorf("nil ForceFlush err = %v", err)
	}
	if err := tracer.Shutdown(context.Background()); err != nil {
		t.Errorf("nil Shutdown err = %v", err)
	}
}

func TestRecordLLMCallEmitsInvocationAndModelSpans(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	tracer.RecordLLMCall(context.Background(), LLMCallParams{
		AgentID:      "agent-1",
		AgentName:    "Classifier",
		ModelID:      "mistral-small-latest",
		Prompt:       "classify",
		Response:     "done",
		InputTokens:  10,
		OutputTokens: 5,
		LatencyMS:    50,
	})

	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("want 2 spans (invocation + model_call), got %d", len(spans))
	}
	var invocation, model sdktrace.ReadOnlySpan
	for _, s := range spans {
		switch s.Name() {
		case "governance.invocation":
			invocation = s
		case "governance.model_call":
			model = s
		}
	}
	if invocation == nil || model == nil {
		t.Fatalf("missing spans: invocation=%v model=%v", invocation != nil, model != nil)
	}
	if got := attrMap(invocation.Attributes())["llm.token_count.total"].AsInt64(); got != 15 {
		t.Errorf("invocation total tokens = %d, want 15", got)
	}
	if got := attrMap(model.Attributes())["llm.model_name"].AsString(); got != "mistral-small-latest" {
		t.Errorf("model_name = %q", got)
	}
	if model.Parent().SpanID() != invocation.SpanContext().SpanID() {
		t.Error("model_call should nest under the invocation")
	}
}

func TestStartInvocationGeneratesJournalIDWhenEmpty(t *testing.T) {
	tracer, recorder := newTestTracer(t)
	_, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a"})
	inv.End(InvocationEndParams{})

	attrs := attrMap(recorder.Ended()[0].Attributes())
	if attrs["session.id"].AsString() == "" {
		t.Error("session.id empty; JournalID should be auto-generated when not supplied")
	}
	if attrs["aigentrail.journal.id"].AsString() == "" {
		t.Error("journal.id empty; should be auto-generated when not supplied")
	}
}

func TestNewWithoutAPIKeyReturnsErr(t *testing.T) {
	t.Setenv("GENTRAIL_API_KEY", "")
	_, err := New(context.Background())
	if err != ErrMissingAPIKey {
		t.Errorf("err = %v, want ErrMissingAPIKey", err)
	}
}
