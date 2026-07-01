package gentrail

import (
	"context"
	"regexp"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// Client-side PII redaction scrubs high-confidence sensitive values out of a
// span's free-text attributes before the span leaves the process, leaving a
// typed placeholder ([EMAIL], [SSN], [CREDIT_CARD], [AWS_KEY]). This is the
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

var (
	emailRe  = regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`)
	ssnRe    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	awsKeyRe = regexp.MustCompile(`\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b`)
	// A card candidate is 13-19 digits with optional space/dash separators; the
	// Luhn check keeps random long numbers from being redacted.
	cardRe = regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`)
)

// redactString replaces high-confidence PII in s with a typed placeholder.
// Order matters: emails and SSNs are removed before the card scan so their
// digits can't be mistaken for a card number.
func redactString(s string) string {
	if s == "" {
		return s
	}
	s = emailRe.ReplaceAllString(s, "[EMAIL]")
	s = ssnRe.ReplaceAllString(s, "[SSN]")
	s = awsKeyRe.ReplaceAllString(s, "[AWS_KEY]")
	s = cardRe.ReplaceAllStringFunc(s, func(m string) string {
		if luhnValid(m) {
			return "[CREDIT_CARD]"
		}
		return m
	})
	return s
}

// luhnValid reports whether the 13-19 digits in s pass the Luhn checksum;
// non-digit separators are ignored.
func luhnValid(s string) bool {
	digits := make([]int, 0, len(s))
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits = append(digits, int(r-'0'))
		}
	}
	if len(digits) < 13 || len(digits) > 19 {
		return false
	}
	sum, double := 0, false
	for i := len(digits) - 1; i >= 0; i-- {
		d := digits[i]
		if double {
			if d *= 2; d > 9 {
				d -= 9
			}
		}
		sum += d
		double = !double
	}
	return sum%10 == 0
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
			if red := redactString(raw); red != raw {
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
