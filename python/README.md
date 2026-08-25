# gentrail

Governance SDK for AI agents. It captures compliance-evidence-grade telemetry
from an agent run and, when enabled, enforces policy inline before a tool call
executes.

A Go SDK with the same span shape lives in [`../go/`](../go/) (`go get
github.com/aigentrail/sdk/go`).

## Quickstart

```bash
pip install "gentrail[strands]"
export GENTRAIL_API_KEY="sk-..."
```

```python
import gentrail
from strands import Agent

g = gentrail.init()
agent = Agent(model=model, tools=tools, hooks=[g.hook()])
agent("Reconcile the Q3 invoices")
```

That is the whole integration. `init()` reads the environment, builds the
governance tracer and the policy enforcer, and `hook()` returns a Strands
`HookProvider` that captures prompts, chain-of-thought, and tool calls, ships
them over OTLP, registers the agent on its first invocation, and enforces
verdicts before a tool runs. Use one `hook()` per agent. Whatever is not
configured stays off: with no API key the agent still runs, capture-only.

## Configuration

All through environment variables:

- `GENTRAIL_API_KEY`: enables OTLP export of governance spans.
- `OTEL_EXPORTER_OTLP_ENDPOINT`: collector base URL, default
  `https://otel.gentrail.ai`.
- `OTEL_EXPORTER_OTLP_HEADERS`: standard OTel header list; when set it replaces
  the SDK's default Basic auth header.
- `GENTRAIL_DECIDE_ENDPOINT`: enables inline enforcement (see below).
- `GENTRAIL_REDACT_PII`: set to `false` to disable client-side PII redaction.
- `GENTRAIL_GATE_TIMEOUT_SECONDS`: how long a gated tool call waits for human
  approval, default 120.

If your application already configures an OpenTelemetry `TracerProvider`, the
SDK attaches its exporter to it as an extra span processor instead of replacing
it; a fresh provider is installed only when none exists.

## PII redaction

The OTLP exporter redacts high-confidence PII (emails, SSNs, credit cards, AWS
keys) from span input and output values before they leave the process, replacing
each with a typed placeholder like `[EMAIL]`, so the raw value never reaches the
collector while the data class stays visible for governance. On by default; opt
out with `GENTRAIL_REDACT_PII=false` or `create_governance_tracer(redact=False)`.

## Inline enforcement (opt-in)

The async backend evaluator only sees a trace after a tool has already run, so
it can detect but never prevent. Enforcement happens here, in the before-tool-call
hook: the SDK asks the backend for a verdict on the proposed tool call and stops
it before it executes.

It is opt-in and fails open. Set both environment variables to turn it on:

```bash
export GENTRAIL_DECIDE_ENDPOINT="https://your-dashboard.example"
export GENTRAIL_API_KEY="sk-..."
```

With these set, a `BLOCK` verdict cancels the tool call (the agent receives an
error tool result and the tool never runs). A `GATE` verdict also stops the call
pending human approval. A backend error never breaks the agent: the call is
allowed and enforcement is skipped for that step.

## Advanced: raw capture surfaces

`init()` and `hook()` compose lower-level pieces that remain importable for
consumers that need them directly:

- `event_normalizer.py`: the canonical `AgentEvent` type and the in-memory
  `event_store`. The hook appends every lifecycle event here, including an
  automatic `AGENT_REGISTERED` on the agent's first invocation.
- `evidence_ledger.py`: a local append-only audit log with integrity hashes;
  the hook seals one `DecisionJournal` per invocation.
- `otel_exporter.py`: `create_governance_tracer()` / `get_governance_tracer()`
  build the OTLP pipeline without the rest of the SDK.
- `enforcement.py`: `PolicyEnforcer` is the raw decide/gate client.

## Develop

```bash
uv sync --extra strands
ruff check .
python3 tests/test_enforcement.py
python3 tests/test_init.py
```
