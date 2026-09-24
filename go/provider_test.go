package gentrail

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

type capturedOTLPRequest struct {
	path          string
	authorization string
	body          []byte
}

func clearGentrailEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"GENTRAIL_API_KEY", "AIGENTRAIL_API_KEY", "GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_REDACT_PII",
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
		"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
		"OTEL_EXPORTER_OTLP_CERTIFICATE", "OTEL_EXPORTER_OTLP_INSECURE",
	} {
		t.Setenv(key, "")
	}
}

func newOTLPCollector(t *testing.T) (*httptest.Server, <-chan capturedOTLPRequest) {
	t.Helper()
	requests := make(chan capturedOTLPRequest, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var reader io.Reader = r.Body
		if r.Header.Get("Content-Encoding") == "gzip" {
			gz, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Errorf("gzip body: %v", err)
				return
			}
			reader = gz
		}
		body, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("read body: %v", err)
			return
		}
		requests <- capturedOTLPRequest{path: r.URL.Path, authorization: r.Header.Get("Authorization"), body: body}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, requests
}

func receiveOTLPRequest(t *testing.T, requests <-chan capturedOTLPRequest) capturedOTLPRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(5 * time.Second):
		t.Fatal("collector received no export")
		return capturedOTLPRequest{}
	}
}

func TestNewSendsBearerAuthToTracesPath(t *testing.T) {
	clearGentrailEnv(t)
	srv, requests := newOTLPCollector(t)
	tracer, err := New(context.Background(), WithAPIKey("sk-test"), WithEndpoint(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	defer tracer.Shutdown(context.Background())

	tracer.RecordLLMCall(context.Background(), LLMCallParams{AgentID: "a", ModelID: "m", Prompt: "p"})
	if err := tracer.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	request := receiveOTLPRequest(t, requests)
	if request.path != "/v1/traces" {
		t.Errorf("path = %q, want /v1/traces", request.path)
	}
	if request.authorization != "Bearer sk-test" {
		t.Errorf("authorization = %q, want Bearer sk-test", request.authorization)
	}
}

func TestNewDefersToOTLPHeaderEnv(t *testing.T) {
	for _, headerEnv := range []string{"OTEL_EXPORTER_OTLP_HEADERS", "OTEL_EXPORTER_OTLP_TRACES_HEADERS"} {
		t.Run(headerEnv, func(t *testing.T) {
			clearGentrailEnv(t)
			t.Setenv(headerEnv, "Authorization=Basic%20from-env")
			srv, requests := newOTLPCollector(t)
			tracer, err := New(context.Background(), WithAPIKey("sk-test"), WithEndpoint(srv.URL))
			if err != nil {
				t.Fatal(err)
			}
			defer tracer.Shutdown(context.Background())

			tracer.RecordLLMCall(context.Background(), LLMCallParams{AgentID: "a", ModelID: "m"})
			if err := tracer.ForceFlush(context.Background()); err != nil {
				t.Fatal(err)
			}

			if got := receiveOTLPRequest(t, requests).authorization; got != "Basic from-env" {
				t.Errorf("authorization = %q, want the env-configured header", got)
			}
		})
	}
}

func TestLoadConfigReadsOTLPEnv(t *testing.T) {
	clearGentrailEnv(t)
	cfg := loadConfig(nil)
	if cfg.endpoint != DefaultEndpoint || cfg.insecure || cfg.certificateFile != "" || !cfg.redact || cfg.envHeadersConfigured {
		t.Errorf("empty env config = %+v", cfg)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.test")
	t.Setenv("OTEL_EXPORTER_OTLP_CERTIFICATE", "/etc/ca.pem")
	t.Setenv("GENTRAIL_REDACT_PII", "FALSE")
	for _, value := range []string{"true", "1", "yes", "TRUE", "Yes"} {
		t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", value)
		cfg := loadConfig(nil)
		if !cfg.insecure {
			t.Errorf("OTEL_EXPORTER_OTLP_INSECURE=%q not honoured", value)
		}
		if cfg.endpoint != "https://collector.test" || cfg.certificateFile != "/etc/ca.pem" || cfg.redact {
			t.Errorf("env config = %+v", cfg)
		}
	}
	t.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "no")
	if loadConfig(nil).insecure {
		t.Error("OTEL_EXPORTER_OTLP_INSECURE=no must stay secure")
	}
	if cfg := loadConfig([]Option{WithEndpoint("https://option.test"), WithRedaction(true)}); cfg.endpoint != "https://option.test" || !cfg.redact {
		t.Errorf("options must override env: %+v", cfg)
	}
}

func TestNewFailsOnUnreadableCertificateFile(t *testing.T) {
	clearGentrailEnv(t)
	_, err := New(context.Background(), WithAPIKey("sk"), WithCertificateFile(t.TempDir()+"/missing.pem"))
	if err == nil || errors.Is(err, ErrMissingAPIKey) {
		t.Errorf("err = %v, want a certificate read error", err)
	}
}

func TestHalfConfiguredTracingWarning(t *testing.T) {
	clearGentrailEnv(t)
	if got := halfConfiguredTracingWarning(); got != "" {
		t.Errorf("unconfigured env must stay silent, got %q", got)
	}
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://collector.test")
	if got := halfConfiguredTracingWarning(); !strings.Contains(got, "OTEL_EXPORTER_OTLP_ENDPOINT") {
		t.Errorf("endpoint-only warning = %q", got)
	}
	t.Setenv("AIGENTRAIL_API_KEY", "sk-old")
	if got := halfConfiguredTracingWarning(); !strings.Contains(got, "AIGENTRAIL_API_KEY") {
		t.Errorf("legacy key warning = %q", got)
	}
}

func TestInstrumentRedactsForeignSpansOnTheWire(t *testing.T) {
	clearGentrailEnv(t)
	srv, requests := newOTLPCollector(t)
	provider := sdktrace.NewTracerProvider()
	defer provider.Shutdown(context.Background())

	processor, err := Instrument(provider, WithAPIKey("sk-test"), WithEndpoint(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, span := provider.Tracer("app").Start(context.Background(), "chat")
	span.SetAttributes(
		attribute.String("gen_ai.prompt", "mail jane.doe@example.com"),
		attribute.String("gen_ai.system", "openai"),
	)
	span.End()
	if err := processor.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	request := receiveOTLPRequest(t, requests)
	if request.path != "/v1/traces" || request.authorization != "Bearer sk-test" {
		t.Errorf("request path=%q auth=%q", request.path, request.authorization)
	}
	for _, want := range []string{"[EMAIL]", "openai", redactionAppliedAttributeKey} {
		if !bytes.Contains(request.body, []byte(want)) {
			t.Errorf("exported payload missing %q", want)
		}
	}
	if bytes.Contains(request.body, []byte("jane.doe@example.com")) {
		t.Error("raw email reached the collector")
	}
}

func TestInstrumentWithoutRedactionExportsRawValues(t *testing.T) {
	clearGentrailEnv(t)
	t.Setenv("GENTRAIL_REDACT_PII", "false")
	srv, requests := newOTLPCollector(t)
	provider := sdktrace.NewTracerProvider()
	defer provider.Shutdown(context.Background())

	processor, err := Instrument(provider, WithAPIKey("sk-test"), WithEndpoint(srv.URL))
	if err != nil {
		t.Fatal(err)
	}
	_, span := provider.Tracer("app").Start(context.Background(), "chat")
	span.SetAttributes(attribute.String("gen_ai.prompt", "mail jane.doe@example.com"))
	span.End()
	if err := processor.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	body := receiveOTLPRequest(t, requests).body
	if !bytes.Contains(body, []byte("jane.doe@example.com")) || bytes.Contains(body, []byte(redactionAppliedAttributeKey)) {
		t.Error("with redaction disabled the span must export raw and unstamped")
	}
}

func TestInstrumentWithoutAPIKeyReturnsErrMissingAPIKey(t *testing.T) {
	clearGentrailEnv(t)
	processor, err := Instrument(sdktrace.NewTracerProvider())
	if !errors.Is(err, ErrMissingAPIKey) || processor != nil {
		t.Errorf("Instrument = (%v, %v), want (nil, ErrMissingAPIKey)", processor, err)
	}
}

func TestInstrumentPanicsOnNilProvider(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("Instrument(nil) must panic")
		}
	}()
	Instrument(nil, WithAPIKey("sk"))
}
