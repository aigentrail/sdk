# Gentrail SDKs

Governance SDKs for AI agents: they capture compliance-evidence-grade telemetry
from an agent run, redact PII before it leaves the process, and, when enabled,
enforce policy inline before a tool call executes. All three emit the same
OpenTelemetry span shape, so one ingest path accepts traces from any runtime.

- [`python/`](python/) is the Python SDK (`pip install "gentrail[strands]"`).
- [`go/`](go/) is the Go SDK (`go get github.com/aigentrail/sdk/go`).
- [`js/gentrail-ai/`](js/gentrail-ai/) is the TypeScript SDK (`npm install @gentrail/ai`).

## Feature parity

Every SDK ships the same core features. Framework adapters are native to each
ecosystem.

| Feature | Python | Go | TypeScript |
| --- | --- | --- | --- |
| One-call setup from the environment | `init()` | `Init(ctx)` | `init()` |
| Governance tracer: invocation, model, tool, and one-shot LLM spans | `GovernanceTracer` | `Tracer` | `GovernanceTracer` |
| Enforced decision stamped on tool spans | `enforced_decision=` | `EnforcedDecision` | `enforcedDecision` |
| PII redaction before export | `redact_pii` | built into the exporter | `redactPII` |
| Redaction of GenAI attributes on spans other libraries emit | `instrument()` | `Instrument()` | `instrument()` |
| Inline enforcement: decide (fails open) and gate wait (fails closed) | `PolicyEnforcer` | `Enforcer` | `PolicyEnforcer` |
| One decide-and-gate cycle | `enforce()` | `Enforcer.Enforce` | `PolicyEnforcer.enforce` |
| Evidence ledger with sealed, hash-verified decision journals | `EvidenceLedger` | `EvidenceLedger` | `EvidenceLedger` |
| HTTP model-call instrumentation | `tracer.httpx_transport()` | `Tracer.HTTPRoundTripper` | `tracer.fetch()` |
| Framework adapters | Strands, LangChain, OpenAI Agents | none | Vercel AI SDK (`guardTools`) |

Parity is enforced by shared specs in [`spec/`](spec/) that every SDK's tests
read: the PII redaction corpus, decision-journal hash vectors (SHA-256 over RFC
8785 canonical JSON), enforcement outcomes, and the required span names and
attributes. The PII detector's rule data is vendored byte-identically into each
SDK by `scripts/sync-pii-data.sh`, and CI checks the copies match.

Two guarantees hold in every SDK:

- PII detection runs on RE2, so scanning is linear-time in the input and a
  crafted tool result cannot stall the agent (`google-re2` in Python, `re2` in
  TypeScript, the standard library in Go).
- Only spans Gentrail ingests leave the process. The governance tracer runs on
  a private provider, and every export path drops spans without a GenAI signal
  (`spec/spans.json` `export_filter`), so an app's HTTP and database spans are
  never sent.

Requirements: Python 3.10+, Go 1.25+, Node 22+.

## Configuration

All SDKs read the same environment variables:

- `GENTRAIL_API_KEY`: enables tracing to Gentrail.
- `OTEL_EXPORTER_OTLP_ENDPOINT`: collector override (default `https://otel.gentrail.ai`).
- `GENTRAIL_DECIDE_ENDPOINT`: enables inline enforcement.
- `GENTRAIL_GATE_TIMEOUT_SECONDS`: how long a gated tool call waits for approval (default 120).
- `GENTRAIL_REDACT_PII=false`: disables client-side PII redaction.
