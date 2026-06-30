package gentrail

// Option configures a Tracer at construction time.
type Option func(*config)

type config struct {
	apiKey            string
	endpoint          string
	certificateFile   string
	insecure          bool
	setGlobalProvider bool
}

// WithAPIKey sets the bearer credential used for OTLP Basic auth. Overrides
// GENTRAIL_API_KEY.
func WithAPIKey(key string) Option {
	return func(c *config) { c.apiKey = key }
}

// WithEndpoint sets the OTLP HTTP collector base URL (no path suffix).
// Overrides OTEL_EXPORTER_OTLP_ENDPOINT. The exporter appends /v1/traces.
func WithEndpoint(url string) Option {
	return func(c *config) { c.endpoint = url }
}

// WithCertificateFile sets a CA bundle path for TLS verification.
func WithCertificateFile(path string) Option {
	return func(c *config) { c.certificateFile = path }
}

// WithInsecure disables TLS certificate verification. Use only for local
// collectors with self-signed certs.
func WithInsecure() Option {
	return func(c *config) { c.insecure = true }
}

// WithSetGlobalProvider installs the Tracer's TracerProvider as the
// process-global one via otel.SetTracerProvider. Off by default to avoid
// surprising callers who already manage their own provider.
func WithSetGlobalProvider() Option {
	return func(c *config) { c.setGlobalProvider = true }
}
