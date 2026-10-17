# SDK conformance

Python, Go and TypeScript implement one governance contract. Language syntax and
framework adapters differ; shared capabilities and execution guarantees do not.
Every shared feature change must update all three implementations and its common
vectors before the task is complete. Each SDK's CI reads these files directly.

| Contract | Shared proof |
| --- | --- |
| Policy allow/block and approval outcomes | `enforce_vectors.json` |
| Strict quota receipts: one-time authority, request/revision/window binding, expiry, exhaustion, same-origin controls | `admission_vectors.json` |
| Decision-linked execution evidence and full original argument hashes | `observation_vectors.json` |
| PII detection and redaction | `pii_conformance.json` plus identical detector data |
| Journal canonicalization and integrity hashes | `journal_vectors.json` |
| Governance span names, attributes and export isolation | `spans.json`, `export_filter_vectors.json` |

Each implementation also tests its native HTTP transport and execution boundary:
approval precedes reservation, consume is not retried after a lost reply, replay
cannot execute twice, redirects never forward credentials, and receipts are
bounded. Python covers synchronous and async clients plus Strands, LangChain
and OpenAI Agents; TypeScript covers its async client and Vercel `guardTools`;
Go covers context-aware enforcement and its shared host admission client.
Framework availability is ecosystem-specific and is recorded in the root matrix.

Strict admission is an explicit opt-in with an agent-bound credential. Policy
reads do not grant execution authority. The server remains the sole owner of
policy evaluation and quota state. Attempts remain charged after consumption,
including crashes, tool failures and later host refusals. Telemetry-only AWS
integrations cannot claim tool-execution enforcement.

These suites prove client conformance and transport behavior. They do not prove
that an application calls its enforcement boundary for every tool, live AWS
latency, or deployment/release availability. Native framework tests isolate the
adapter seam; they are not full hosted-provider runs.
