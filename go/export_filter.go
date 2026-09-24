package gentrail

import (
	"context"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

var (
	genAISignalAttributePrefixes = []string{"gen_ai.", "ai.", "llm.", "openinference.", "aigentrail."}
	genAISignalAttributeKeys     = map[string]bool{"session.id": true, "agent.name": true, "tool.name": true}
)

func carriesGenAISignal(attributes []attribute.KeyValue) bool {
	for _, kv := range attributes {
		key := string(kv.Key)
		if genAISignalAttributeKeys[key] {
			return true
		}
		for _, prefix := range genAISignalAttributePrefixes {
			if strings.HasPrefix(key, prefix) {
				return true
			}
		}
	}
	return false
}

// genAISignalExporter drops spans Gentrail does not ingest, so an app's HTTP
// and database spans, whose attributes redaction never inspects, never leave
// the process.
type genAISignalExporter struct {
	sdktrace.SpanExporter
}

func (e genAISignalExporter) ExportSpans(ctx context.Context, spans []sdktrace.ReadOnlySpan) error {
	kept := make([]sdktrace.ReadOnlySpan, 0, len(spans))
	for _, span := range spans {
		if carriesGenAISignal(span.Attributes()) {
			kept = append(kept, span)
		}
	}
	if len(kept) == 0 {
		return nil
	}
	return e.SpanExporter.ExportSpans(ctx, kept)
}
