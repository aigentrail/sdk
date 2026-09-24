package gentrail

import (
	"context"
	"encoding/json"
	"os"
	"regexp"
	"slices"
	"sort"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestRedactPII(t *testing.T) {
	cases := []struct{ in, want string }{
		{"reach me at jane.doe@example.com please", "reach me at [EMAIL] please"},
		{"SSN 123-45-6789 on file", "SSN [SSN] on file"},
		{"SSN 123456789 on file", "SSN [SSN] on file"},
		{"key AKIAZ4QXN7P2LRT5WVKB leaked", "key [AWS_KEY] leaked"},
		{"card 4111111111111111 charged", "card [CREDIT_CARD] charged"},
		{"card 4111 1111 1111 1111 charged", "card [CREDIT_CARD] charged"},
		{"amex 378282246310005 ok", "amex [CREDIT_CARD] ok"},
		{"pay DE89370400440532013000 today", "pay [IBAN] today"},
		{"phone 555-123-4567", "phone [PHONE]"},
		{"token ghp_R8x2mQ9vL4kT7nB1cZ5wY3pH6jD0fG2sA9eK", "token [SECRET]"},
		{`{"email":"a@b.co","ssn":"111-22-3333"}`, `{"email":"[EMAIL]","ssn":"[SSN]"}`},
		{"a@b.com and 123-45-6789", "[EMAIL] and [SSN]"},
		{"just a normal sentence with 42 items", "just a normal sentence with 42 items"},
		{"", ""},
	}
	for _, c := range cases {
		if got := redactPII(c.in); got != c.want {
			t.Errorf("redactPII(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestRedactPIILeavesLookAlikes(t *testing.T) {
	for _, s := range []string{
		"order 4111111111111112 shipped",
		"ref 1234567890123456 pending",
		"ref 555-123-4567",
		"id 12345",
		"icon@2x.png",
		"api_key = $API_KEY",
		"key AKIAIOSFODNN7EXAMPLE",
	} {
		if got := redactPII(s); got != s {
			t.Errorf("redactPII(%q) redacted a look-alike to %q", s, got)
		}
	}
}

var placeholderTokenRe = regexp.MustCompile(`\[(AWS_KEY|CREDIT_CARD|EMAIL|IBAN|PHONE|SECRET|SSN)\]`)

func TestRedactPIIConformsToGentrailCorpus(t *testing.T) {
	raw, err := os.ReadFile("pii_conformance.json")
	if err != nil {
		t.Fatalf("read corpus: %v", err)
	}
	var corpus struct {
		Classes []string `json:"classes"`
		Cases   []struct {
			Name   string   `json:"name"`
			Fields []string `json:"fields"`
			Want   []string `json:"want"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatalf("unmarshal corpus: %v", err)
	}
	if len(corpus.Cases) == 0 {
		t.Fatal("corpus has no cases")
	}
	if want := []string{"AWS_KEY", "CREDIT_CARD", "EMAIL", "IBAN", "PHONE", "SECRET", "SSN"}; !slices.Equal(corpus.Classes, want) {
		t.Fatalf("corpus classes %v, SDK placeholders cover %v", corpus.Classes, want)
	}
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			found := map[string]bool{}
			for _, field := range c.Fields {
				redacted := redactPII(field)
				if len(c.Want) == 0 && redacted != field {
					t.Errorf("redactPII(%q) = %q, want unchanged", field, redacted)
				}
				for _, m := range placeholderTokenRe.FindAllStringSubmatch(redacted, -1) {
					found[m[1]] = true
				}
			}
			got := make([]string, 0, len(found))
			for class := range found {
				got = append(got, class)
			}
			sort.Strings(got)
			if !slices.Equal(got, c.Want) {
				t.Errorf("placeholders after redaction %v, want %v", got, c.Want)
			}
		})
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
