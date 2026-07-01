package gentrail

import (
	"context"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestRedactString(t *testing.T) {
	cases := []struct{ in, want string }{
		{"reach me at jane.doe@example.com please", "reach me at [EMAIL] please"},
		{"SSN 123-45-6789 on file", "SSN [SSN] on file"},
		{"key AKIAIOSFODNN7EXAMPLE leaked", "key [AWS_KEY] leaked"},
		{"card 4111111111111111 charged", "card [CREDIT_CARD] charged"},
		{"card 4111 1111 1111 1111 charged", "card [CREDIT_CARD] charged"},
		{"amex 378282246310005 ok", "amex [CREDIT_CARD] ok"},
		{`{"email":"a@b.co","ssn":"111-22-3333"}`, `{"email":"[EMAIL]","ssn":"[SSN]"}`},
		{"a@b.com and 123-45-6789", "[EMAIL] and [SSN]"},
		{"just a normal sentence with 42 items", "just a normal sentence with 42 items"},
		{"", ""},
	}
	for _, c := range cases {
		if got := redactString(c.in); got != c.want {
			t.Errorf("redactString(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A 16-digit number that fails Luhn is not a card and must survive: Luhn is what
// keeps random order and account numbers from being redacted.
func TestRedactStringLeavesNonLuhn(t *testing.T) {
	for _, s := range []string{
		"order 4111111111111112 shipped",
		"ref 1234567890123456 pending",
		"phone 555-123-4567",
		"id 12345",
	} {
		if got := redactString(s); got != s {
			t.Errorf("redactString(%q) redacted a non-card to %q", s, got)
		}
	}
}

func TestLuhnValid(t *testing.T) {
	for _, s := range []string{"4111111111111111", "4111 1111 1111 1111", "378282246310005", "5500005555555559"} {
		if !luhnValid(s) {
			t.Errorf("luhnValid(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"4111111111111112", "1234567890123456", "12345", "", "not a number"} {
		if luhnValid(s) {
			t.Errorf("luhnValid(%q) = true, want false", s)
		}
	}
}

type captureExporter struct{ spans []sdktrace.ReadOnlySpan }

func (c *captureExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	c.spans = append(c.spans, spans...)
	return nil
}

func (c *captureExporter) Shutdown(context.Context) error { return nil }

// The exporter decorator must scrub input/output values before the underlying
// exporter sees them, and leave structured attributes (even PII-shaped ones,
// like an agent name that looks like an email) untouched.
func TestRedactingExporterScrubsValueAttributes(t *testing.T) {
	sink := &captureExporter{}
	tp := sdktrace.NewTracerProvider(sdktrace.WithSyncer(redactingExporter{SpanExporter: sink}))
	_, span := tp.Tracer("test").Start(context.Background(), "invoke")
	span.SetAttributes(
		attribute.String("input.value", "email jane@acme.com"),
		attribute.String("output.value", "ssn 123-45-6789, card 4111111111111111"),
		attribute.String("agent.name", "ops@corp.com"),
	)
	span.End()

	if len(sink.spans) != 1 {
		t.Fatalf("got %d spans, want 1", len(sink.spans))
	}
	got := map[string]string{}
	for _, kv := range sink.spans[0].Attributes() {
		got[string(kv.Key)] = kv.Value.AsString()
	}
	if got["input.value"] != "email [EMAIL]" {
		t.Errorf("input.value = %q, want redacted", got["input.value"])
	}
	if got["output.value"] != "ssn [SSN], card [CREDIT_CARD]" {
		t.Errorf("output.value = %q, want redacted", got["output.value"])
	}
	if got["agent.name"] != "ops@corp.com" {
		t.Errorf("agent.name = %q, want untouched (not a value field)", got["agent.name"])
	}
}
