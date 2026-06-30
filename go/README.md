# gentrail (Go)

The Go governance SDK for Gentrail. It emits OpenTelemetry spans for agent
invocations, LLM calls, and tool calls over OTLP/HTTP, with the same span shape
as the Python SDK so one ingest path accepts traces from either runtime.

## Install

```bash
go get github.com/aigentrail/sdk/go
```

## Usage

```go
import "github.com/aigentrail/sdk/go"

tracer, err := gentrail.New(ctx)
if err != nil {
	log.Fatal(err)
}
defer tracer.Shutdown(context.Background())

ctx, inv := tracer.StartInvocation(ctx, gentrail.InvocationParams{
	AgentID:     "tool-classifier",
	AgentName:   "ToolClassifier",
	UserMessage: prompt,
})
tracer.RecordModelCall(ctx, gentrail.ModelCallParams{
	ModelID:      "mistral-small-latest",
	Prompt:       prompt,
	ResponseText: response,
	InputTokens:  inTok,
	OutputTokens: outTok,
})
inv.End(gentrail.InvocationEndParams{Response: response, TotalTokens: inTok + outTok})
```

The import path ends in `/go` because the module lives in this repo's `go/`
directory, while the package itself is `gentrail`, so call sites read
`gentrail.New`. Go binds the identifier from the package clause, so no import
alias is needed.

`New` reads `GENTRAIL_API_KEY` and `OTEL_EXPORTER_OTLP_ENDPOINT` from the
environment by default; both can be overridden via options.
