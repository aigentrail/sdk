package gentrail

import (
	"context"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Client-side PII redaction scrubs high-confidence sensitive values out of a
// span's free-text attributes before the span leaves the process, leaving a
// typed placeholder ([EMAIL], [SSN], [CREDIT_CARD], [IBAN], [PHONE], [AWS_KEY], [SECRET]). This is the
// privacy guarantee: the raw value never reaches the collector, while the
// placeholder preserves the governance signal (Gentrail can still see which
// data class flowed). It runs as an exporter decorator so every exported span
// is covered regardless of which instrumentation set the attribute. On by
// default; disable with WithRedaction(false) or GENTRAIL_REDACT_PII=false.

// redactedKeys are the free-text span attributes scanned for PII. Structured
// attributes (ids, agent names, token counts) are left untouched.
var redactedKeys = map[string]bool{
	"input.value":  true,
	"output.value": true,
}

// redactingExporter wraps a SpanExporter, scrubbing PII from each span's
// free-text attributes before delegating the export.
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

// redactSpan returns s with its free-text value attributes scrubbed, or s
// unchanged when nothing matched (so unaffected spans keep their original type).
func redactSpan(s sdktrace.ReadOnlySpan) sdktrace.ReadOnlySpan {
	orig := s.Attributes()
	out := make([]attribute.KeyValue, len(orig))
	changed := false
	for i, kv := range orig {
		if redactedKeys[string(kv.Key)] && kv.Value.Type() == attribute.STRING {
			raw := kv.Value.AsString()
			if red := redactPII(raw); red != raw {
				out[i] = attribute.String(string(kv.Key), red)
				changed = true
				continue
			}
		}
		out[i] = kv
	}
	if !changed {
		return s
	}
	return redactedSpan{ReadOnlySpan: s, attrs: out}
}
