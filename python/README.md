# gentrail

Governance SDK for AI agents. It captures compliance-evidence-grade telemetry
from an agent run and, when enabled, enforces policy inline before a tool call
executes.

A Go SDK with the same span shape lives in [`../go/`](../go/) (`go get
github.com/aigentrail/sdk/go`).

## Operation admission

The unreleased D3 SDK requires an agent-bound API key and registered tool IDs.
See [release preparation](../RELEASE.md) for qualification and rollout.

```python
from gentrail.enforcement import PolicyEnforcer, enforce

enforcer = PolicyEnforcer(
    endpoint,
    bound_agent_key,
    tool_ids={"issue_refund": registered_refund_tool_id},
)
allowed, message = enforce(
    enforcer, "issue_refund", arguments,
    agent_id="billing-agent", request_id=tool_call_id,
)
if not allowed:
    raise RuntimeError(message)
result = issue_refund(**arguments)
```

`AsyncPolicyEnforcer` and `enforce_async` use the same contract. Configured
enforcement always fails closed and requires admission for every executable
operation, including those without quotas. Missing mappings block before a
decision request. You can instead pass `tool_id` explicitly to `decide` or
`enforce`. Mappings are copied at configuration time and limited to 128 entries.

Pass the configured enforcer to `GentrailGovernanceHook(enforcer=...)`,
`enforcement_middleware(enforcer=...)` or `enforcement_guardrail(enforcer=...)`.
Sync/async conversion preserves its mappings, deadlines, clock and identity
generator. `from_env()` reads endpoint/key configuration; a returned enforcer
still requires explicit tool IDs before it can authorize execution.

Enforcement resolves every required approval, then reserves and consumes one
policy-bound lease before returning permission to run. Unknown outcomes,
outages, missing admission, malformed or expired receipts, foreign links,
redirects and lost consume responses block the call. Low-level `decide` and
`await_gate` do not grant execution authority.

A repeated request ID cannot reuse a consumed grant. Closed and uncertain
attempts return different recovery guidance. Never retry execution automatically
after a lost consume reply or failed evidence report; check the attempt's outcome
first. Consumption remains charged after a tool failure, host refusal or crash.
For fresh evaluation, use a new `request_id` and set `parent_request_id` to the
earlier request. The new decision does not inherit approvals.

Admission uses `operation_v1` controls, a nine-second total budget, at most three
seconds per network operation, a 30-second lease limit and 64 KiB receipt limits.
Consume is never retried. Approval status responses are also limited to 64 KiB.

## Quickstart

```bash
pip install "gentrail[strands]"
export GENTRAIL_API_KEY="sk-..."
```

```python
import gentrail
from strands import Agent

g = gentrail.init(tool_ids=registered_tool_ids)
agent = Agent(model=model, tools=tools, hooks=[g.hook()])
agent("Reconcile the Q3 invoices")
```

That is the whole integration. `init()` reads the environment, builds the
governance tracer and the policy enforcer, and `hook()` returns a Strands
`HookProvider` that captures prompts, chain-of-thought, and tool calls, ships
them over OTLP, registers the agent on its first invocation, and enforces
verdicts before a tool runs. Use one `hook()` per agent. Whatever is not
configured stays off: with no API key the agent still runs, capture-only.

### OpenAI Agents SDK

```bash
pip install "gentrail[openai-agents]"
```

```python
from agents import function_tool
from gentrail.openai_agents import enforcement_guardrail
from gentrail.enforcement import PolicyEnforcer

enforcer = PolicyEnforcer(endpoint, bound_agent_key, tool_ids={"run_sql": registered_sql_tool_id})

@function_tool(tool_input_guardrails=[enforcement_guardrail(enforcer)])
def run_sql(database: str, sql: str) -> str: ...
```

A tool input guardrail that asks the decide endpoint before the tool runs.
BLOCK rejects the call with the policy message; GATE holds it until a human
approves in the Gentrail dashboard.

### LangChain / LangGraph

```bash
pip install "gentrail[langchain]"
```

```python
from langchain.agents import create_agent
from gentrail.langchain import enforcement_middleware
from gentrail.enforcement import PolicyEnforcer

enforcer = PolicyEnforcer(endpoint, bound_agent_key, tool_ids={"run_sql": registered_sql_tool_id})

agent = create_agent(
    model=model,
    tools=tools,
    middleware=[enforcement_middleware(enforcer, agent_id="reporter")],
)
```

Agent middleware wrapping every tool call, sync and async. Same verdicts: a
blocked or unapproved call becomes an error `ToolMessage` and the tool never
executes.

## Bring your own telemetry

Frameworks that emit OpenTelemetry GenAI telemetry natively (Strands with
`strands-agents[otel]`, Google ADK, Pydantic AI, LangChain with
`LANGSMITH_OTEL_ENABLED`, the Vercel AI SDK) do not need the SDK to build
spans: the Gentrail backend ingests `gen_ai.*`, `ai.*`, and OpenInference
telemetry directly. This is the recommended integration for those frameworks.
What the SDK still adds is client-side PII redaction and export to Gentrail:

```python
import gentrail

gentrail.instrument()
```

`instrument()` attaches a `GentrailSpanProcessor` to your application's
`TracerProvider` (pass yours with `instrument(provider=...)`; a fresh one is
installed only when none exists). The processor redacts PII from `gen_ai.*`,
`ai.*`, and OpenInference input/output attributes before any value leaves the
process, stamps `aigentrail.redaction.applied` on spans it changed, and ships
them to the Gentrail collector over OTLP. Spans without a GenAI signal (your
database and HTTP spans) are dropped rather than exported. Other exporters on
the provider keep the raw spans. Without `GENTRAIL_API_KEY` it returns `None`
and the app runs unchanged.

The governance tracer behind `init()` never touches your provider: it runs on
its own, so your spans cannot reach Gentrail through it, and its spans still
join your trace through the shared OpenTelemetry context.

Inline enforcement stays separate: add the enforcement adapter for your
framework (above) to get BLOCK and GATE verdicts before a tool runs.

## Configuration

Tool mappings are explicit SDK options. Tracing and endpoint settings use:

- `GENTRAIL_API_KEY`: enables OTLP export of governance spans.
- `OTEL_EXPORTER_OTLP_ENDPOINT`: collector base URL, default
  `https://otel.gentrail.ai`.
- `OTEL_EXPORTER_OTLP_HEADERS`: standard OTel header list; when set it replaces
  the SDK's default `Authorization: Bearer <GENTRAIL_API_KEY>` header.
- `GENTRAIL_DECIDE_ENDPOINT`: enables inline enforcement (see below).
- `GENTRAIL_REDACT_PII`: set to `false` to disable client-side PII redaction.
- `GENTRAIL_GATE_TIMEOUT_SECONDS`: how long a gated tool call waits for human
  approval, default 120.

If your application already configures an OpenTelemetry `TracerProvider`, the
SDK attaches its exporter to it as an extra span processor instead of replacing
it; a fresh provider is installed only when none exists.

## PII redaction

The SDK redacts PII from span input and output values before they leave the
process, scanning with RE2 (`google-re2`) so detection is linear-time in the
input, replacing each value with a typed placeholder: `[EMAIL]`, `[SSN]`,
`[CREDIT_CARD]`, `[IBAN]`, `[PHONE]`, `[AWS_KEY]`, or `[SECRET]`. Numbers are
validated (Luhn, SSN area rules, IBAN mod-97) so order ids and look-alikes
survive, and secrets are found with the vendored gitleaks default rules. The raw
value never reaches the collector while the data class stays visible for
governance. The detector matches Gentrail's server-side one, pinned by the
shared corpus in `spec/pii_conformance.json`. This applies to spans the SDK
builds and, via `GentrailSpanProcessor`, to `gen_ai.*`, `ai.*`, and
OpenInference attributes on spans your framework emits itself. On by default;
opt out with `GENTRAIL_REDACT_PII=false` or `instrument(redact=False)`.

## Inline enforcement

Enforcement is optional to configure, but once configured it always fails closed.
Set `GENTRAIL_DECIDE_ENDPOINT` and an agent-bound `GENTRAIL_API_KEY`, then supply
registered tool IDs through `init(tool_ids=...)`, `from_env(tool_ids=...)` or an
explicit enforcer. Unknown mappings, unavailable decisions and missing admission
keep execution blocked. Human approval alone does not authorize execution.

Strands and LangChain snapshot tool input before authorization and use that copy
for execution. Place the enforcement middleware closest to the tool body, after
other middleware has finalized its arguments. Changes made by downstream custom
middleware are outside this enforcement boundary.

## Advanced: raw capture surfaces

`init()` and `hook()` compose lower-level pieces that remain importable for
consumers that need them directly:

- `evidence_ledger.py`: a local audit log of `DecisionJournal`s; the hook seals
  one per invocation. The integrity hash is SHA-256 over the journal's RFC 8785
  canonical JSON, so the Go and JS SDKs produce the same hash for the same
  journal (`spec/journal_vectors.json`). `init()` gives each handle its own
  ledger at `handle.ledger`.
- `otel_exporter.py`: `create_governance_tracer()` / `get_governance_tracer()`
  build the OTLP pipeline without the rest of the SDK. `tracer.httpx_transport()`
  and `tracer.async_httpx_transport()` wrap an httpx client so every request is
  recorded as a model call with latency and status (requires `httpx`).
- `enforcement.py`: `PolicyEnforcer` and its asyncio twin `AsyncPolicyEnforcer`
  are the raw decide/gate clients; `enforce()` / `enforce_async()` run one
  decide-and-gate cycle and return `(allowed, message)`.

## Develop

```bash
uv sync --extra strands
ruff check .
python3 tests/test_enforcement.py
python3 tests/test_init.py
python3 tests/test_parity_spec.py
```

### Linking tool results to decisions

`PolicyEnforcer.decide()` and `AsyncPolicyEnforcer.decide()` return an explicit
`outcome`: `verified`, `request_conflict`, or `unavailable`. A transport failure
returns `BLOCK` with `outcome="unavailable"`.
`BLOCK` and unresolved `GATE` decisions retain their enforcement behavior.

A verified, attributed response can include an immutable `DecisionReference` in
`verdict["observation_reference"]` and a server-provided `observations_url`.
Pass that reference as `decision_reference` to `GovernanceTracer.record_tool_call()`
after the tool actually runs. Supply the full actual arguments as JSON; the
tracer hashes them before redaction and truncation. Changed arguments remain
visible to the backend as an identity mismatch. Invalid references are discarded
without changing permission; invalid recording input raises an error and leaves
an ordinary, unlinked span.

The Strands hook carries references automatically, keeps at most 128 pending
calls, and skips cancelled calls. Evicted or missing references leave results
unlinked. LangChain and OpenAI guardrails enforce permission; callers that record
execution evidence use the tracer explicitly. References link producer reports
and never grant permission or attest that a tool executed.
