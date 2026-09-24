package gentrail

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type spanShape struct {
	Name               string   `json:"name"`
	SpanKind           string   `json:"span_kind"`
	StartAttributes    []string `json:"start_attributes"`
	EndAttributes      []string `json:"end_attributes"`
	Attributes         []string `json:"attributes"`
	OptionalAttributes []string `json:"optional_attributes"`
}

type spanSpec struct {
	Source                       string    `json:"source"`
	ValueRuneLimit               int       `json:"value_rune_limit"`
	RedactedAttributePrefixes    []string  `json:"redacted_attribute_prefixes"`
	RedactionAppliedAttribute    string    `json:"redaction_applied_attribute"`
	EnforcementDecisionAttribute string    `json:"enforcement_decision_attribute"`
	Invocation                   spanShape `json:"invocation"`
	ModelCall                    spanShape `json:"model_call"`
	ToolCall                     spanShape `json:"tool_call"`
}

func loadSpanSpec(t *testing.T) spanSpec {
	t.Helper()
	raw, err := os.ReadFile("../spec/spans.json")
	if err != nil {
		t.Fatalf("read span spec: %v", err)
	}
	var spec spanSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatalf("unmarshal span spec: %v", err)
	}
	if spec.ValueRuneLimit <= 0 {
		t.Fatalf("value_rune_limit = %d, want positive", spec.ValueRuneLimit)
	}
	return spec
}

func newCapturingTracer(t *testing.T) (*Tracer, *captureExporter) {
	t.Helper()
	sink := &captureExporter{}
	provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(sink))
	t.Cleanup(func() { provider.Shutdown(context.Background()) })
	return &Tracer{tracer: provider.Tracer("aigentrail.conformance"), provider: provider}, sink
}

func spanNamed(t *testing.T, spans []sdktrace.ReadOnlySpan, name string) sdktrace.ReadOnlySpan {
	t.Helper()
	for _, s := range spans {
		if s.Name() == name {
			return s
		}
	}
	t.Fatalf("no span named %q exported", name)
	return nil
}

func assertSpanShape(t *testing.T, span sdktrace.ReadOnlySpan, shape spanShape, keys []string) {
	t.Helper()
	attrs := attrMap(span.Attributes())
	for _, key := range keys {
		if _, ok := attrs[key]; !ok {
			t.Errorf("span %q missing attribute %q", span.Name(), key)
		}
	}
	if got := attrs["openinference.span.kind"].AsString(); got != shape.SpanKind {
		t.Errorf("span %q kind = %q, want %q", span.Name(), got, shape.SpanKind)
	}
}

func TestSpansConformToSharedSpec(t *testing.T) {
	spec := loadSpanSpec(t)
	tracer, sink := newCapturingTracer(t)

	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{
		AgentID: "agent-1", AgentName: "Agent", JournalID: "journal-1", UserMessage: "hello",
	})
	tracer.RecordModelCall(ctx, ModelCallParams{ModelID: "m", Prompt: "p", ResponseText: "r", InputTokens: 1, OutputTokens: 2, LatencyMS: 3})
	tracer.RecordToolCall(ctx, ToolCallParams{
		AgentID: "agent-1", AgentName: "Agent", Name: "search_web", Args: "{}", Result: "ok",
		DurationMS: 4, EnforcedDecision: DecisionGate,
	})
	inv.End(InvocationEndParams{Response: "done", TotalTokens: 3, ToolCount: 1, IntegrityHash: "h"})

	invocation := spanNamed(t, sink.spans, spec.Invocation.Name)
	assertSpanShape(t, invocation, spec.Invocation, slices.Concat(spec.Invocation.StartAttributes, spec.Invocation.EndAttributes))
	if got := attrMap(invocation.Attributes())["source"].AsString(); got != spec.Source {
		t.Errorf("source = %q, want %q", got, spec.Source)
	}
	assertSpanShape(t, spanNamed(t, sink.spans, spec.ModelCall.Name), spec.ModelCall,
		slices.Concat(spec.ModelCall.Attributes, spec.ModelCall.OptionalAttributes))
	if spec.ToolCall.Name != "<tool name>" {
		t.Fatalf("tool_call name = %q, want the tool-name placeholder", spec.ToolCall.Name)
	}
	assertSpanShape(t, spanNamed(t, sink.spans, "search_web"), spec.ToolCall,
		slices.Concat(spec.ToolCall.Attributes, spec.ToolCall.OptionalAttributes))
}

func TestSpanValuesTruncateToSharedRuneLimit(t *testing.T) {
	spec := loadSpanSpec(t)
	for _, limit := range []int{maxInputValueRunes, maxOutputValueRunes, maxModelOutputRunes} {
		if limit != spec.ValueRuneLimit {
			t.Errorf("SDK rune limit %d, spec value_rune_limit %d", limit, spec.ValueRuneLimit)
		}
	}
	tracer, sink := newCapturingTracer(t)
	oversized := strings.Repeat("世", spec.ValueRuneLimit+25)
	ctx, inv := tracer.StartInvocation(context.Background(), InvocationParams{AgentID: "a", UserMessage: oversized})
	tracer.RecordModelCall(ctx, ModelCallParams{ModelID: "m", Prompt: oversized, ResponseText: oversized})
	tracer.RecordToolCall(ctx, ToolCallParams{Name: "t", Args: oversized, Result: oversized})
	inv.End(InvocationEndParams{Response: oversized})

	if len(sink.spans) != 3 {
		t.Fatalf("exported %d spans, want 3", len(sink.spans))
	}
	for _, span := range sink.spans {
		attrs := attrMap(span.Attributes())
		for _, key := range []string{"input.value", "output.value"} {
			if got := utf8.RuneCountInString(attrs[key].AsString()); got != spec.ValueRuneLimit {
				t.Errorf("span %q %s has %d runes, want %d", span.Name(), key, got, spec.ValueRuneLimit)
			}
		}
	}
}

func TestSDKAttributeConstantsMatchSharedSpec(t *testing.T) {
	spec := loadSpanSpec(t)
	if !slices.Equal(redactedAttributePrefixes, spec.RedactedAttributePrefixes) {
		t.Errorf("redacted prefixes %v, spec %v", redactedAttributePrefixes, spec.RedactedAttributePrefixes)
	}
	if redactionAppliedAttributeKey != spec.RedactionAppliedAttribute {
		t.Errorf("redaction stamp %q, spec %q", redactionAppliedAttributeKey, spec.RedactionAppliedAttribute)
	}
	if enforcementDecisionAttributeKey != spec.EnforcementDecisionAttribute {
		t.Errorf("enforcement decision key %q, spec %q", enforcementDecisionAttributeKey, spec.EnforcementDecisionAttribute)
	}
	if sourceAttrValue != spec.Source {
		t.Errorf("source %q, spec %q", sourceAttrValue, spec.Source)
	}
}
