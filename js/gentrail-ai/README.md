# @gentrail/ai

Gentrail inline policy enforcement for Vercel AI SDK tools. `guardTools` wraps
each tool's `execute` so the Gentrail decide endpoint rules on the call before
it runs.

## Quickstart

```bash
npm install @gentrail/ai
export GENTRAIL_DECIDE_ENDPOINT="https://your-dashboard.example"
export GENTRAIL_API_KEY="sk-..."
```

```ts
import { streamText } from "ai";
import { guardTools } from "@gentrail/ai";

const result = streamText({
  model,
  tools: guardTools(tools),
  prompt: "Reconcile the Q3 invoices",
});
```

## Verdicts

- `ALLOW` runs the tool unchanged.
- `BLOCK` throws a `GentrailPolicyError` carrying the policy message; the AI
  SDK turns errors thrown inside `execute` into `tool-error` parts, so the
  model sees the message and the run continues.
- `GATE` polls the approval status until a human decides in the Gentrail
  dashboard. Approved runs the tool; denied, expired, or unanswered
  (`GENTRAIL_GATE_TIMEOUT_SECONDS`, default 120) throws like `BLOCK`. The gate
  fails closed.
- A decide transport error fails open: the tool runs and enforcement is
  skipped for that call.

## Options

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

Without an endpoint and API key, `guardTools` returns the tools untouched, so
the integration is safe to leave in place unconfigured. Each decide request
carries the AI SDK `toolCallId` as `request_id`, making backend writes
idempotent under retries.

## Develop

```bash
npm install
npm test
```
