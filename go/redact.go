package gentrail

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Client-side PII redaction scrubs high-confidence sensitive values out of a
// span's free-text attributes before the span leaves the process, leaving a
// typed placeholder ([EMAIL], [SSN], [CREDIT_CARD], [IBAN], [PHONE], [AWS_KEY],
// [SECRET]). The raw value never reaches the collector, while the placeholder
// preserves the governance signal. It runs as an exporter decorator because
// that is the one point where every attribute is final and the SDK owns the
// data: the provider's other exporters keep the raw span.

var redactedAttributePrefixes = []string{"gen_ai.", "ai.", "input.", "output."}

const redactionAppliedAttributeKey = "aigentrail.redaction.applied"

type redactingExporter struct {
	sdktrace.SpanExporter
}

func (e redactingExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	out := make([]sdktrace.ReadOnlySpan, len(spans))
	for i, s := range spans {
		out[i] = redactSpan(s)
	}
	return e.SpanExporter.ExportSpans(ctx, out)
}

// redactedSpan overrides Attributes on an embedded ReadOnlySpan. Embedding the
// interface promotes its sealed private() method, so the wrapper still counts
// as a ReadOnlySpan; only the attribute slice is replaced.
type redactedSpan struct {
	sdktrace.ReadOnlySpan
	attrs []attribute.KeyValue
}

func (r redactedSpan) Attributes() []attribute.KeyValue { return r.attrs }

// redactSpan returns s unchanged when nothing matched, so unaffected spans
// keep their original type and carry no redaction stamp.
func redactSpan(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	original := s.Attributes()
	redacted := make([]attribute.KeyValue, 0, len(original)+1)
	changed := false
	for _, kv := range original {
		if kv.Key == redactionAppliedAttributeKey {
			continue
		}
		replacement, replaced := redactAttribute(kv)
		changed = changed || replaced
		redacted = append(redacted, replacement)
	}
	if !changed {
		return s
	}
	redacted = append(redacted, attribute.Bool(redactionAppliedAttributeKey, true))
	return redactedSpan{ReadOnlySpan: s, attrs: redacted}
}

func redactAttribute(kv attribute.KeyValue) (attribute.KeyValue, bool) {
	if !hasRedactedAttributePrefix(string(kv.Key)) {
		return kv, false
	}
	switch kv.Value.Type() {
	case attribute.STRING:
		raw := kv.Value.AsString()
		scrubbed := redactPII(raw)
		return attribute.String(string(kv.Key), scrubbed), scrubbed != raw
	case attribute.STRINGSLICE:
		values := kv.Value.AsStringSlice()
		changed := false
		for i, raw := range values {
			scrubbed := redactPII(raw)
			changed = changed || scrubbed != raw
			values[i] = scrubbed
		}
		return attribute.StringSlice(string(kv.Key), values), changed
	default:
		return kv, false
	}
}

func hasRedactedAttributePrefix(key string) bool {
	for _, prefix := range redactedAttributePrefixes {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}
