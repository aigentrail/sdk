package gentrail

import (
	"context"
	"errors"
	"log"
)

// Gentrail is the handle Init returns: the governance tracer, the policy
// enforcer, and a fresh evidence ledger. Tracer and Enforcer are nil when
// their configuration is absent; every method on them and on the handle is
// nil-safe, so an unconfigured app still runs.
type Gentrail struct {
	Tracer   *Tracer
	Enforcer *Enforcer
	Ledger   *EvidenceLedger
}

// Init configures the SDK from the environment and options. Tracing needs
// GENTRAIL_API_KEY (see New); inline enforcement additionally needs
// GENTRAIL_DECIDE_ENDPOINT (see NewEnforcerFromEnv). Whatever is unset stays
// off. A tracer that fails to build for any other reason, such as an
// unreadable certificate file, is logged and left nil rather than failing
// the app.
func Init(ctx context.Context, opts ...Option) *Gentrail {
	tracer, err := New(ctx, opts...)
	if err != nil && !errors.Is(err, ErrMissingAPIKey) {
		log.Printf("gentrail: governance tracing disabled: %v", err)
	}
	return &Gentrail{
		Tracer:   tracer,
		Enforcer: NewEnforcerFromEnv(),
		Ledger:   NewEvidenceLedger(nil, nil),
	}
}

// Flush exports every queued span. A nil handle or tracer is a no-op.
func (g *Gentrail) Flush(ctx context.Context) error {
	if g == nil {
		return nil
	}
	return g.Tracer.ForceFlush(ctx)
}

// Shutdown flushes and releases the tracer. A nil handle or tracer is a
// no-op.
func (g *Gentrail) Shutdown(ctx context.Context) error {
	if g == nil {
		return nil
	}
	return g.Tracer.Shutdown(ctx)
}
