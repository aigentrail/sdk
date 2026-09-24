package gentrail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// DefaultEndpoint is the OTLP HTTPS collector used when no endpoint is
// configured via WithEndpoint or OTEL_EXPORTER_OTLP_ENDPOINT.
const DefaultEndpoint = "https://otel.gentrail.ai"

// ErrMissingAPIKey is returned by New and Instrument when neither WithAPIKey
// nor GENTRAIL_API_KEY supplies a credential.
var ErrMissingAPIKey = errors.New("gentrail: API key not set (use WithAPIKey or GENTRAIL_API_KEY)")

// New constructs a Tracer that ships governance spans over OTLP/HTTP. It
// reads GENTRAIL_API_KEY, OTEL_EXPORTER_OTLP_ENDPOINT,
// OTEL_EXPORTER_OTLP_CERTIFICATE, OTEL_EXPORTER_OTLP_INSECURE, and
// GENTRAIL_REDACT_PII from the environment unless overridden by options.
// When OTEL_EXPORTER_OTLP_HEADERS or OTEL_EXPORTER_OTLP_TRACES_HEADERS is set
// those headers replace the default Bearer authorization. Returns
// ErrMissingAPIKey if no credential is configured.
func New(ctx context.Context, opts ...Option) (*Tracer, error) {
	cfg := loadConfig(opts)
	exporter, err := newOTLPExporter(ctx, cfg)
	if err != nil {
		return nil, err
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(governanceSpanExporter(exporter, cfg.redact)))
	if cfg.setGlobalProvider {
		otel.SetTracerProvider(provider)
	}
	return &Tracer{
		tracer:       provider.Tracer("aigentrail.governance"),
		provider:     provider,
		redactValues: cfg.redact,
	}, nil
}

// Instrument attaches a batch span processor to an application-owned
// provider so spans from other instrumentation (gen_ai.*, Vercel ai.*,
// OpenInference) ship to Gentrail. Unless redaction is disabled, PII in
// gen_ai.*, ai.*, input.*, and output.* string attributes is redacted on the
// export path and changed spans carry aigentrail.redaction.applied=true; the
// provider's other exporters still see the raw span. Configuration matches
// New. Returns ErrMissingAPIKey if no credential is configured.
func Instrument(provider *sdktrace.TracerProvider, opts ...Option) (sdktrace.SpanProcessor, error) {
	if provider == nil {
		panic("gentrail: Instrument requires a non-nil TracerProvider")
	}
	cfg := loadConfig(opts)
	exporter, err := newOTLPExporter(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	processor := sdktrace.NewBatchSpanProcessor(governanceSpanExporter(exporter, cfg.redact))
	provider.RegisterSpanProcessor(processor)
	return processor, nil
}

// Shutdown flushes any pending spans and releases the underlying provider.
// Safe to call at most once. A nil Tracer is a no-op.
func (t *Tracer) Shutdown(ctx context.Context) error {
	if t == nil {
		return nil
	}
	return t.provider.Shutdown(ctx)
}

// ForceFlush blocks until the batch span processor has exported all
// currently-queued spans, or until ctx is done. A nil Tracer is a no-op.
func (t *Tracer) ForceFlush(ctx context.Context) error {
	if t == nil {
		return nil
	}
	return t.provider.ForceFlush(ctx)
}

func newOTLPExporter(ctx context.Context, cfg config) (sdktrace.SpanExporter, error) {
	if cfg.apiKey == "" {
		if warning := halfConfiguredTracingWarning(); warning != "" {
			log.Print(warning)
		}
		return nil, ErrMissingAPIKey
	}
	exporterOpts, err := buildExporterOptions(cfg)
	if err != nil {
		return nil, err
	}
	exporter, err := otlptracehttp.New(ctx, exporterOpts...)
	if err != nil {
		return nil, fmt.Errorf("gentrail: create OTLP exporter: %w", err)
	}
	return exporter, nil
}

func governanceSpanExporter(exporter sdktrace.SpanExporter, redact bool) sdktrace.SpanExporter {
	if !redact {
		return exporter
	}
	return redactingExporter{SpanExporter: exporter}
}

// halfConfiguredTracingWarning is non-empty when the environment looks like it
// meant to enable tracing, because a silent no-op there once cost a day of
// debugging after the AIGENTRAIL_API_KEY -> GENTRAIL_API_KEY rename.
func halfConfiguredTracingWarning() string {
	if os.Getenv("AIGENTRAIL_API_KEY") != "" {
		return "gentrail: AIGENTRAIL_API_KEY is set but this SDK reads GENTRAIL_API_KEY; governance tracing disabled"
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") != "" {
		return "gentrail: OTEL_EXPORTER_OTLP_ENDPOINT is set but GENTRAIL_API_KEY is not; governance tracing disabled"
	}
	return ""
}

func buildExporterOptions(cfg config) ([]otlptracehttp.Option, error) {
	tracesURL, err := tracesEndpointURL(cfg.endpoint)
	if err != nil {
		return nil, err
	}
	opts := []otlptracehttp.Option{otlptracehttp.WithEndpointURL(tracesURL)}
	if !cfg.envHeadersConfigured {
		opts = append(opts, otlptracehttp.WithHeaders(map[string]string{"Authorization": "Bearer " + cfg.apiKey}))
	}
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, err
	}
	if tlsConfig != nil {
		opts = append(opts, otlptracehttp.WithTLSClientConfig(tlsConfig))
	}
	return opts, nil
}

func buildTLSConfig(cfg config) (*tls.Config, error) {
	if !cfg.insecure && cfg.certificateFile == "" {
		return nil, nil
	}
	tlsConfig := &tls.Config{InsecureSkipVerify: cfg.insecure}
	if cfg.certificateFile != "" {
		pool, err := loadCertPool(cfg.certificateFile)
		if err != nil {
			return nil, err
		}
		tlsConfig.RootCAs = pool
	}
	return tlsConfig, nil
}

func loadCertPool(path string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("gentrail: read certificate %q: %w", path, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("gentrail: no PEM certificates found in %q", path)
	}
	return pool, nil
}

// tracesEndpointURL appends /v1/traces to the collector base URL, the same
// path the Python exporter builds. A scheme-less endpoint is HTTPS.
func tracesEndpointURL(endpoint string) (string, error) {
	scheme, rest, hasScheme := strings.Cut(endpoint, "://")
	if !hasScheme {
		scheme, rest = "https", endpoint
	}
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("gentrail: endpoint %q must use http or https", endpoint)
	}
	base := scheme + "://" + strings.TrimRight(rest, "/")
	parsed, err := url.Parse(base)
	if err != nil {
		return "", fmt.Errorf("gentrail: parse endpoint %q: %w", endpoint, err)
	}
	if parsed.Host == "" {
		return "", fmt.Errorf("gentrail: endpoint %q has no host", endpoint)
	}
	return base + "/v1/traces", nil
}
