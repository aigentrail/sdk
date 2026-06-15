# aigentrail

Governance SDK for AI agents. It captures compliance-evidence-grade telemetry
from an agent run and, when enabled, enforces policy inline before a tool call
executes.

## Install

```bash
pip install "aigentrail[strands]"
```

The `strands` extra pulls in the Strands hook integration. Omit it if you only
use the event normalizer, evidence ledger, or OTLP exporter directly.

## What it does

The SDK composes four pieces:

- `hooks.py` - a Strands `HookProvider` that intercepts every lifecycle event
  (prompts, chain-of-thought, tool calls and results) and seals a per-invocation
  decision journal.
- `event_normalizer.py` - turns provider-specific events into one canonical
  event type.
- `evidence_ledger.py` - a local append-only audit log with integrity hashes.
- `otel_exporter.py` - pushes the captured spans over OTLP.

## Inline enforcement (opt-in)

The async backend evaluator only sees a trace after a tool has already run, so
it can detect but never prevent. Enforcement happens here, in the before-tool-call
hook: the SDK asks the backend for a verdict on the proposed tool call and stops
it before it executes.

It is opt-in and fails open. Set both environment variables to turn it on:

```bash
export AIGENTRAIL_DECIDE_ENDPOINT="https://your-dashboard.example"
export AIGENTRAIL_API_KEY="sk-..."
```

With these set, a `BLOCK` verdict cancels the tool call (the agent receives an
error tool result and the tool never runs). A `GATE` verdict also stops the call
pending human approval. A backend error never breaks the agent: the call is
allowed and enforcement is skipped for that step.

## Develop

```bash
uv sync --extra strands
ruff check .
python3 tests/test_enforcement.py
```
