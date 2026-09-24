# gentrail (Go)

The Go governance SDK for Gentrail. It emits OpenTelemetry spans for agent
invocations, LLM calls, and tool calls over OTLP/HTTP, enforces policy on tool
calls before they run, and seals decision journals as evidence. Span shape,
enforcement semantics, and journal hashes match the Python SDK; the shared
vectors in `../spec` pin all three.

## Install

```bash
go get github.com/aigentrail/sdk/go
```

The import path ends in `/go` because the module lives in this repo's `go/`
directory, while the package itself is `gentrail`, so call sites read
`gentrail.Init`. Go binds the identifier from the package clause, so no import
alias is needed.

## Quick start

```go
import "github.com/aigentrail/sdk/go"

g := gentrail.Init(ctx)
defer g.Shutdown(context.Background())
```

`Init(ctx, opts...) *Gentrail` never fails. The handle carries:

- `Tracer`: built by `New`; nil without `GENTRAIL_API_KEY`.
- `Enforcer`: built by `NewEnforcerFromEnv`; nil unless both
  `GENTRAIL_DECIDE_ENDPOINT` and `GENTRAIL_API_KEY` are set.
- `Ledger`: a fresh `EvidenceLedger`.

Every method on a nil `Tracer`, `Enforcer`, or `*Gentrail` is a no-op (or
allows the call), so an unconfigured app still runs. `g.Flush(ctx)` and
`g.Shutdown(ctx)` flush and release the tracer.

## Tracing

```go
ctx, inv := g.Tracer.StartInvocation(ctx, gentrail.InvocationParams{
	AgentID:     "tool-classifier",
	AgentName:   "ToolClassifier",
	UserMessage: prompt,
})
g.Tracer.RecordModelCall(ctx, gentrail.ModelCallParams{
	ModelID:      "mistral-small-latest",
	Prompt:       prompt,
	ResponseText: response,
	InputTokens:  inTok,
	OutputTokens: outTok,
})
inv.End(gentrail.InvocationEndParams{Response: response, TotalTokens: inTok + outTok})
```

`New(ctx, opts...)` reads the same environment as the Python SDK:

| Variable | Effect |
| --- | --- |
| `GENTRAIL_API_KEY` | Required; sent as `Authorization: Bearer <key>` |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | Collector base URL, default `https://otel.gentrail.ai`; spans go to `/v1/traces` |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` | When set, sent instead of the Bearer header |
| `OTEL_EXPORTER_OTLP_CERTIFICATE` | CA bundle for TLS verification |
| `OTEL_EXPORTER_OTLP_INSECURE` | `true`, `1`, or `yes` skips TLS verification |
| `GENTRAIL_REDACT_PII` | `false` disables client-side PII redaction |

Options (`WithAPIKey`, `WithEndpoint`, `WithCertificateFile`, `WithInsecure`,
`WithRedaction`, `WithSetGlobalProvider`) override the environment. Without a
key `New` returns `ErrMissingAPIKey`, and logs a warning when
`AIGENTRAIL_API_KEY` or `OTEL_EXPORTER_OTLP_ENDPOINT` suggests tracing was
meant to be on.

## Bring your own telemetry

```go
processor, err := gentrail.Instrument(provider)
```

`Instrument(provider *sdktrace.TracerProvider, opts ...Option)
(sdktrace.SpanProcessor, error)` registers a Gentrail batch span processor on
an app-owned provider, configured like `New`. Spans from other GenAI
instrumentation ship to Gentrail with PII redacted from every `gen_ai.*`,
`ai.*`, `input.*`, and `output.*` string attribute; redacted spans carry
`aigentrail.redaction.applied=true`. Spans without a GenAI signal (no
`gen_ai.*`, `ai.*`, `llm.*`, `openinference.*`, `aigentrail.*`, `session.id`,
`agent.name`, or `tool.name` attribute) are never exported, so database and HTTP
spans stay in the process. The provider's other exporters still see
the raw span.

## Enforcement

```go
allowed, message := g.Enforcer.Enforce(ctx, "issue_refund", args,
	gentrail.WithAgentID("billing-agent"))
if !allowed {
	g.Tracer.RecordToolCall(ctx, gentrail.ToolCallParams{
		AgentID:          "billing-agent",
		AgentName:        "Billing Agent",
		Name:             "issue_refund",
		Result:           message,
		EnforcedDecision: gentrail.DecisionBlock,
	})
	return message
}
```

`Enforce` runs one decide-and-gate cycle. `BLOCK` returns `false` with the
verdict message (or `"<decision> by policy <rule>"`). `GATE` waits up to the
gate timeout (`GENTRAIL_GATE_TIMEOUT_SECONDS`, default 120) for a human
approval: approved returns `true`; denied, expired, or unanswered returns
`false` with `"<message> (approval <status>)"`. Anything else is allowed.
`Decide` fails open on backend errors; `AwaitGate` fails closed.

Set `ToolCallParams.EnforcedDecision` to the verdict (`DecisionBlock` or
`DecisionGate`) when recording a cancelled tool call; it is exported as
`aigentrail.enforcement.decision` so the evaluator marks the matching
violation as prevented.

## Evidence ledger

```go
journal := g.Ledger.Create("billing-agent", "Billing Agent")
journal.UserMessage = prompt
journal.ToolCalls = append(journal.ToolCalls, gentrail.ToolCallRecord{
	ToolName: "issue_refund",
	ToolArgs: map[string]any{"order_id": 4411},
})
hash, _ := g.Ledger.Seal(journal.JournalID)
```

`DecisionJournal.Seal(now)` stamps the journal with the sha256 hex of its RFC
8785 canonical JSON (`CanonicalJSON`), identical to the Python SDK's hash for
the same journal. `NewEvidenceLedger(now, newJournalID)` accepts an injected
clock and id generator for tests; nil defaults to `time.Now` and
`inv-YYYY-MMDD-xxxxxx` ids. The ledger also offers `Get`, `All`, `ByAgent`, and
`Clear`.
