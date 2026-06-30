# Gentrail SDKs

Governance SDKs for AI agents: they capture compliance-evidence-grade telemetry
from an agent run and, when enabled, enforce policy inline before a tool call
executes. Both emit the same OpenTelemetry span shape, so one ingest path accepts
traces from either runtime.

- [`python/`](python/) is the Python SDK (`pip install "gentrail[strands]"`).
- [`go/`](go/) is the Go SDK (`go get github.com/aigentrail/sdk/go`).
