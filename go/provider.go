package gentrail

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// DefaultEndpoint is the OTLP HTTPS collector used when no endpoint is
// configured via WithEndpoint or OTEL_EXPORTER_OTLP_ENDPOINT.
const DefaultEndpoint = "https://otel.gentrail.ai"

// ErrMissingAPIKey is returned by New when neither WithAPIKey nor
// GENTRAIL_API_KEY supplies a credential.
var ErrMissingAPIKey = errors.New("gentrail: API key not set (use WithAPIKey or GENTRAIL_API_KEY)")

// New constructs a Tracer that ships governance spans over OTLP/HTTP. It
// reads GENTRAIL_API_KEY and OTEL_EXPORTER_OTLP_ENDPOINT from the
// environment unless overridden by options. Returns ErrMissingAPIKey if no
// credential is configured.
func New(ctx context.Context, opts ...Option) (*Tracer, error) {
	cfg := config{
		apiKey:   os.Getenv("GENTRAIL_API_KEY"),
		endpoint: os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.apiKey == "" {
		return nil, ErrMissingAPIKey
	}
	if cfg.endpoint == "" {
		cfg.endpoint = DefaultEndpoint
	}

	exporterOpts, err := buildExporterOptions(cfg)
	if err != nil {
		return nil, err
	}
	exporter, err := otlptracehttp.New(ctx, exporterOpts...)
	if err != nil {
		return nil, fmt.Errorf("gentrail: create OTLP exporter: %w", err)
	}

	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter))
	if cfg.setGlobalProvider {
		otel.SetTracerProvider(provider)
	}
	return &Tracer{
		tracer:   provider.Tracer("aigentrail.governance"),
		provider: provider,
	}, nil
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

func buildExporterOptions(cfg config) ([]otlptracehttp.Option, error) {
	endpointHost, urlPath, err := splitEndpoint(cfg.endpoint)
	if err != nil {
		return nil, err
	}
	credentials := base64.StdEncoding.EncodeToString([]byte(cfg.apiKey + ":" + cfg.apiKey))
	opts := []otlptracehttp.Option{
		otlptracehttp.WithEndpoint(endpointHost),
		otlptracehttp.WithURLPath(urlPath),
		otlptracehttp.WithHeaders(map[string]string{
			"Authorization": "Basic " + credentials,
		}),
	}
	if cfg.insecure {
		opts = append(opts, otlptracehttp.WithInsecure(), otlptracehttp.WithTLSClientConfig(&tls.Config{InsecureSkipVerify: true}))
	}
	if cfg.certificateFile != "" {
		pool, err := loadCertPool(cfg.certificateFile)
		if err != nil {
			return nil, err
		}
		opts = append(opts, otlptracehttp.WithTLSClientConfig(&tls.Config{RootCAs: pool}))
	}
	return opts, nil
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

// splitEndpoint turns "https://host:4318" or "http://host:4318/v1" into
// (host:port, "/v1/traces") as expected by otlptracehttp.WithEndpoint +
// WithURLPath. A port-less host is pinned to the scheme default (443/80) because
// WithEndpoint would otherwise assume 4318, which a proxy on 443 can't serve.
func splitEndpoint(endpoint string) (host, urlPath string, err error) {
	trimmed := strings.TrimRight(endpoint, "/")
	defaultPort := "443"
	if strings.HasPrefix(trimmed, "https://") {
		trimmed = strings.TrimPrefix(trimmed, "https://")
	} else if strings.HasPrefix(trimmed, "http://") {
		defaultPort = "80"
		trimmed = strings.TrimPrefix(trimmed, "http://")
	}
	if trimmed == "" {
		return "", "", fmt.Errorf("gentrail: empty endpoint")
	}
	host, urlPath = trimmed, "/v1/traces"
	if i := strings.Index(trimmed, "/"); i >= 0 {
		host, urlPath = trimmed[:i], trimmed[i:]+"/v1/traces"
	}
	if !strings.Contains(host, ":") {
		host += ":" + defaultPort
	}
	return host, urlPath, nil
}
