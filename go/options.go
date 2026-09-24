package gentrail

import (
	"os"
	"strings"
)

// Option configures a Tracer at construction time.
type Option func(*config)

type config struct {
	apiKey               string
	endpoint             string
	certificateFile      string
	insecure             bool
	setGlobalProvider    bool
	redact               bool
	envHeadersConfigured bool
}

// WithAPIKey sets the credential sent as a Bearer token to the collector.
// Overrides GENTRAIL_API_KEY.
func WithAPIKey(key string) Option {
	return func(c *config) { c.apiKey = key }
}

// WithEndpoint sets the OTLP HTTP collector base URL (no path suffix).
// Overrides OTEL_EXPORTER_OTLP_ENDPOINT. The exporter appends /v1/traces.
func WithEndpoint(url string) Option {
	return func(c *config) { c.endpoint = url }
}

// WithCertificateFile sets a CA bundle path for TLS verification. Overrides
// OTEL_EXPORTER_OTLP_CERTIFICATE.
func WithCertificateFile(path string) Option {
	return func(c *config) { c.certificateFile = path }
}

// WithInsecure disables TLS certificate verification. Use only for local
// collectors with self-signed certs. Equivalent to
// OTEL_EXPORTER_OTLP_INSECURE=true.
func WithInsecure() Option {
	return func(c *config) { c.insecure = true }
}

// WithSetGlobalProvider installs the Tracer's TracerProvider as the
// process-global one via otel.SetTracerProvider. Off by default to avoid
// surprising callers who already manage their own provider.
func WithSetGlobalProvider() Option {
	return func(c *config) { c.setGlobalProvider = true }
}

// WithRedaction toggles client-side PII redaction. When enabled (the default),
// high-confidence PII in span input and output values is replaced with a typed
// placeholder ([EMAIL], [SSN], [CREDIT_CARD], [AWS_KEY]) before the span leaves
// the process, so the raw value never reaches the collector. Overrides
// GENTRAIL_REDACT_PII.
func WithRedaction(enabled bool) Option {
	return func(c *config) { c.redact = enabled }
}

func loadConfig(opts []Option) config {
	cfg := config{
		apiKey:               os.Getenv("GENTRAIL_API_KEY"),
		endpoint:             os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"),
		certificateFile:      os.Getenv("OTEL_EXPORTER_OTLP_CERTIFICATE"),
		insecure:             insecureFromEnv(),
		redact:               !strings.EqualFold(os.Getenv("GENTRAIL_REDACT_PII"), "false"),
		envHeadersConfigured: os.Getenv("OTEL_EXPORTER_OTLP_HEADERS") != "" || os.Getenv("OTEL_EXPORTER_OTLP_TRACES_HEADERS") != "",
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.endpoint == "" {
		cfg.endpoint = DefaultEndpoint
	}
	return cfg
}

func insecureFromEnv() bool {
	switch strings.ToLower(os.Getenv("OTEL_EXPORTER_OTLP_INSECURE")) {
	case "true", "1", "yes":
		return true
	default:
		return false
	}
}
