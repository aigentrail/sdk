// Package gentrail is the Go governance SDK for Gentrail. It emits
// OpenTelemetry spans for agent invocations, LLM calls, and tool calls,
// shipping them over OTLP/HTTP to the Gentrail collector, enforces policy on
// tool calls before they run, and seals decision journals as tamper-evident
// evidence.
//
// The span shape, enforcement semantics, and journal hashing match the Python
// SDK, pinned by the shared vectors in the repository's spec directory, so the
// same ingest path accepts traces from either runtime.
//
// # Setup
//
// Init reads the environment and returns a handle whose Tracer, Enforcer, and
// Ledger are ready to use. Tracer is nil without GENTRAIL_API_KEY and Enforcer
// is nil without GENTRAIL_DECIDE_ENDPOINT; every method on them is nil-safe,
// so an unconfigured app still runs.
//
// New builds just the tracer. It reads GENTRAIL_API_KEY,
// OTEL_EXPORTER_OTLP_ENDPOINT (default https://otel.gentrail.ai, spans go to
// /v1/traces), OTEL_EXPORTER_OTLP_CERTIFICATE, OTEL_EXPORTER_OTLP_INSECURE,
// and GENTRAIL_REDACT_PII; options override each. The API key is sent as a
// Bearer token unless OTEL_EXPORTER_OTLP_HEADERS or
// OTEL_EXPORTER_OTLP_TRACES_HEADERS is set, in which case those headers are
// sent instead.
//
// # Bring your own telemetry
//
// Instrument attaches a Gentrail batch span processor to an application-owned
// TracerProvider, so spans from other GenAI instrumentation (gen_ai.*, Vercel
// ai.*, OpenInference input.* and output.*) ship to Gentrail alongside the
// app's own exporters.
//
// # Enforcement
//
// Enforcer.Enforce runs one decide-and-gate cycle before a tool call:
// BLOCK returns (false, message); GATE waits for a human approval and returns
// (true, "") only when approved; anything else is allowed. Decide fails open
// on backend errors while AwaitGate fails closed. Record a cancelled call with
// ToolCallParams.EnforcedDecision so the evaluator marks its violation as
// prevented.
//
// # Evidence ledger
//
// EvidenceLedger stores DecisionJournals. DecisionJournal.Seal stamps a
// journal with the sha256 of its RFC 8785 canonical JSON (see CanonicalJSON),
// the same hash every Gentrail SDK computes for the same journal.
//
// # PII redaction
//
// Client-side PII redaction is on by default: emails, SSNs, credit cards,
// IBANs, phone numbers, AWS keys, and secrets in governance span values and in
// gen_ai.*, ai.*, input.*, and output.* string attributes are replaced with a
// typed placeholder before the span leaves the process. Changed spans carry
// aigentrail.redaction.applied=true. Disable with WithRedaction(false) or
// GENTRAIL_REDACT_PII=false.
//
// # Example
//
//	g := gentrail.Init(ctx)
//	defer g.Shutdown(context.Background())
//
//	ctx, inv := g.Tracer.StartInvocation(ctx, gentrail.InvocationParams{
//		AgentID:     "billing-agent",
//		AgentName:   "Billing Agent",
//		UserMessage: prompt,
//	})
//	allowed, message := g.Enforcer.Enforce(ctx, "issue_refund", args, gentrail.WithAgentID("billing-agent"))
//	if !allowed {
//		g.Tracer.RecordToolCall(ctx, gentrail.ToolCallParams{
//			AgentID:          "billing-agent",
//			AgentName:        "Billing Agent",
//			Name:             "issue_refund",
//			Result:           message,
//			EnforcedDecision: gentrail.DecisionBlock,
//		})
//	}
//	inv.End(gentrail.InvocationEndParams{Response: response})
package gentrail
