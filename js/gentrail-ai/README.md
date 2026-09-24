# @gentrail/ai

Gentrail SDK for JavaScript and TypeScript agents: governance tracing, PII
redaction, inline policy enforcement, and evidence capture. Feature parity with
the Gentrail Python and Go SDKs; spans, redaction, journal hashes, and
enforcement verdicts are pinned by the same shared specs.

Requires Node.js 22 or newer. PII detection runs on RE2 through the `re2`
native addon, which ships prebuilt binaries for Linux (glibc and musl), macOS,
and Windows on x64 and arm64; other platforms build it from source. The addon
installs through an npm install script, so if your npm or CI blocks install
scripts, allow it for `re2` (for example `npm install-scripts approve re2` on
npm 11).

## Quickstart

```bash
npm install @gentrail/ai
export GENTRAIL_API_KEY="sk-..."
export GENTRAIL_DECIDE_ENDPOINT="https://your-dashboard.example"  # optional, enables enforcement
```

```ts
import { init } from "@gentrail/ai";

const gentrail = init();
// gentrail.tracer    GovernanceTracer, or null without GENTRAIL_API_KEY
// gentrail.enforcer  PolicyEnforcer, or null without GENTRAIL_DECIDE_ENDPOINT + GENTRAIL_API_KEY
// gentrail.ledger    EvidenceLedger, always available
await gentrail.shutdown();
```

`init()` never throws. Whatever is unconfigured stays off, so the integration is
safe to leave in place. An unreadable `OTEL_EXPORTER_OTLP_CERTIFICATE` logs a
warning and leaves tracing off.

## Environment

| Variable                                                          | Effect                                                                   |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------ |
| `GENTRAIL_API_KEY`                                                | Enables tracing (and enforcement with a decide endpoint)                 |
| `GENTRAIL_DECIDE_ENDPOINT`                                        | Enables inline policy enforcement                                        |
| `OTEL_EXPORTER_OTLP_ENDPOINT`                                     | Collector base URL, default `https://otel.gentrail.ai`                   |
| `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_EXPORTER_OTLP_TRACES_HEADERS` | Replace the default `Authorization: Bearer $GENTRAIL_API_KEY`            |
| `OTEL_EXPORTER_OTLP_CERTIFICATE`                                  | PEM file trusted as the collector CA                                     |
| `OTEL_EXPORTER_OTLP_INSECURE=true`                                | Skips certificate verification; the URL scheme still picks http or https |
| `GENTRAIL_REDACT_PII=false`                                       | Disables client-side PII redaction                                       |
| `GENTRAIL_GATE_TIMEOUT_SECONDS`                                   | How long a GATE waits for a human, default 120                           |

Setting `AIGENTRAIL_API_KEY` or `OTEL_EXPORTER_OTLP_ENDPOINT` without
`GENTRAIL_API_KEY` logs a warning instead of silently disabling tracing.

## Inline enforcement for Vercel AI SDK tools

`guardTools` wraps each tool's `execute` so the Gentrail decide endpoint rules
on the call before it runs.

```ts
import { streamText } from "ai";
import { guardTools } from "@gentrail/ai";

const result = streamText({
  model,
  tools: guardTools(tools, { agentId: "billing-agent" }),
  prompt: "Reconcile the Q3 invoices",
});
```

- `ALLOW` runs the tool unchanged.
- `BLOCK` throws a `GentrailPolicyError` carrying the policy message; the AI
  SDK turns errors thrown inside `execute` into `tool-error` parts, so the
  model sees the message and the run continues.
- `GATE` polls the approval status until a human decides in the Gentrail
  dashboard. Approved runs the tool; denied, expired, or unanswered throws like
  `BLOCK`. The gate fails closed.
- A decide transport error fails open: the tool runs and enforcement is
  skipped for that call.

```ts
guardTools(tools, {
  endpoint,            // default GENTRAIL_DECIDE_ENDPOINT
  apiKey,              // default GENTRAIL_API_KEY
  agentId,             // scopes agent-targeted and windowed rules
  invocationId,        // joins the enforcement record to your trace
  decideTimeoutMs,     // default 3000
  gateTimeoutMs,       // default GENTRAIL_GATE_TIMEOUT_SECONDS * 1000
  gatePollIntervalMs,  // default 2000
});
```

Without an endpoint and API key, `guardTools` returns the tools untouched. Each
decide request carries the AI SDK `toolCallId` as `request_id`, making backend
writes idempotent under retries.

## Enforcement for any framework

`PolicyEnforcer` is the framework-neutral client behind `guardTools`.

```ts
import { PolicyEnforcer } from "@gentrail/ai";

const enforcer = PolicyEnforcer.fromEnv(); // null when unconfigured
const outcome = await enforcer?.enforce(
  "wire_money",
  { amount: 5000 },
  {
    agentId: "treasury-agent",
    requestId: toolCallId, // synthesized when absent
  },
);
if (outcome && !outcome.allowed) {
  return outcome.message; // "Wires need approval. (approval denied)"
}
```

`decide()` fails open to `ALLOW`, `awaitGate()` fails closed to `"timeout"`,
and `invocation_id` defaults to the active OpenTelemetry trace id.

## Governance tracing

```ts
import { createGovernanceTracer } from "@gentrail/ai";

const tracer = createGovernanceTracer(); // null without GENTRAIL_API_KEY
if (tracer) {
  const invocation = tracer.startInvocation({
    agentId: "billing-agent",
    agentName: "Billing Agent",
    journalId: journal.journalId,
    userMessage: "Refund order 4411",
  });
  tracer.recordModelCall(invocation, {
    modelId: "claude-sonnet",
    prompt: "Refund order 4411",
    responseText: "Calling issue_refund",
    inputTokens: 120,
    outputTokens: 48,
    latencyMs: 812,
  });
  tracer.recordToolCall(invocation, {
    agentId: "billing-agent",
    agentName: "Billing Agent",
    name: "issue_refund",
    args: JSON.stringify({ order_id: 4411 }),
    result: "ok",
    durationMs: 41,
    enforcedDecision: undefined, // "BLOCK" or "GATE" when enforcement cancelled the call
  });
  tracer.endInvocation(invocation, {
    response: "Refund issued.",
    totalTokens: 168,
    toolCount: 1,
    integrityHash: journal.seal(),
  });
  await tracer.shutdown();
}
```

Every `input.value` and `output.value` is PII-redacted, then capped at 4000
code points. For single calls, `recordLLMCall({ modelId, prompt, responseText })`
opens the invocation, records the model call, and closes it. Tests and custom
setups can build a tracer from any provider:
`new GovernanceTracer({ tracerProvider, redact: true })`.

### Zero-touch model call capture

`tracer.fetch()` wraps `fetch` so each request is recorded as a one-shot LLM
call: the model is the URL host, the prompt is `METHOD /path`, and the status is
`ok`, `http_<code>` for responses at or above 400, or `error` when the request
throws (the error is rethrown). Latency is recorded in whole milliseconds.

```ts
import OpenAI from "openai";

const client = new OpenAI({ fetch: tracer.fetch() });
```

## Bring your own OpenTelemetry

Frameworks that already emit GenAI telemetry (Vercel AI SDK `ai.*`, `gen_ai.*`,
OpenInference) can export straight to Gentrail. `GentrailSpanProcessor`
batch-exports over OTLP and redacts PII from `gen_ai.*`, `ai.*`, `input.*`, and
`output.*` string attributes on a per-span copy, stamping
`aigentrail.redaction.applied=true` on spans it changed. The app's own
exporters keep the raw span.

```ts
import { NodeTracerProvider } from "@opentelemetry/sdk-trace-node";
import { GentrailSpanProcessor, instrument } from "@gentrail/ai";

new NodeTracerProvider({ spanProcessors: [new GentrailSpanProcessor()] }).register();

// Or let the SDK wire it: attaches to the given provider when it accepts span
// processors, or installs a global provider when the app has none.
instrument();
```

`instrument()` returns `null` without `GENTRAIL_API_KEY`.

### Only GenAI spans leave the process

Every Gentrail export path, the governance tracer and `GentrailSpanProcessor`
alike, with redaction on or off, drops spans that carry no GenAI signal, so an
app's HTTP and database spans never reach Gentrail. A span is exported when at
least one attribute key starts with `gen_ai.`, `ai.`, `llm.`, `openinference.`,
or `aigentrail.`, or equals `session.id`, `agent.name`, or `tool.name`. The
check runs on the span's own attributes before redaction, so the
`aigentrail.redaction.applied` stamp never admits a span. `carriesGenAISignal`
and `GenAISignalSpanExporter` are exported for custom pipelines. The governance
tracer keeps its own private provider and never touches the global one.

## PII redaction

```ts
import { piiFindings, redactPII } from "@gentrail/ai";

redactPII("reach jane@acme.com, SSN 123-45-6789");
// "reach [EMAIL], SSN [SSN]"
piiFindings("key AKIAZ4QXN7P2LRT5WVKB");
// [{ piiClass: "AWS_KEY", start: 4, end: 24, detector: "gitleaks:aws-access-token" }]
```

Classes: `AWS_KEY`, `CREDIT_CARD` (Luhn), `EMAIL`, `IBAN` (mod 97), `PHONE`,
`SECRET` (the vendored gitleaks rule set, with keyword prefilter, entropy
threshold, and allowlists), and `SSN`. Text is normalized first (zero-width
characters dropped, Unicode dashes and spaces folded, NFKC), and finding offsets
point into the original string. The gitleaks rules (MIT, see
`data/gitleaks_LICENSE`) and the IBAN registry ship in `data/`.

Every pattern that scans untrusted text (the gitleaks rules and allowlists and
the detectors' own patterns) runs on RE2, not the backtracking JavaScript
engine, so scan time is linear in the field length and no crafted input can
stall redaction. The gitleaks patterns compile unmodified in their Go syntax,
matching the Go and Python SDKs.

## Evidence ledger

```ts
import { EvidenceLedger } from "@gentrail/ai";

const ledger = new EvidenceLedger();
const journal = ledger.create("billing-agent", "Billing Agent");
journal.userMessage = "Refund order 4411";
journal.toolCalls.push({
  toolName: "issue_refund",
  toolArgs: { order_id: 4411 },
  result: "ok",
  durationMs: 41,
});
const integrityHash = ledger.seal(journal.journalId);
```

Sealing hashes the RFC 8785 canonical JSON of the journal with SHA-256, so a
journal sealed here hashes identically in every Gentrail SDK. `canonicalJson`
is exported for reuse. Inject `clock` and `generateJournalId` for deterministic
tests.

## Develop

```bash
npm install
npm test
```
