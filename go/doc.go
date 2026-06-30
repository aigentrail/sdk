// Package gentrail is the Go governance SDK for Gentrail. It emits
// OpenTelemetry spans for agent invocations, LLM calls, and tool calls,
// shipping them over OTLP/HTTP to the Gentrail collector.
//
// The span shape matches the Python SDK (python/gentrail) so the same
// ingest path accepts traces from either runtime.
//
// # Configuration
//
// New reads GENTRAIL_API_KEY and OTEL_EXPORTER_OTLP_ENDPOINT from the
// environment by default; both can be overridden via options.
//
// # Example
//
//	tracer, err := gentrail.New(ctx)
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer tracer.Shutdown(context.Background())
//
//	ctx, inv := tracer.StartInvocation(ctx, gentrail.InvocationParams{
//		AgentID:     "tool-classifier",
//		AgentName:   "ToolClassifier",
//		JournalID:   journalID,
//		UserMessage: prompt,
//	})
//	tracer.RecordModelCall(ctx, gentrail.ModelCallParams{
//		ModelID:      "mistral-small-latest",
//		Prompt:       prompt,
//		ResponseText: response,
//		InputTokens:  inTok,
//		OutputTokens: outTok,
//	})
//	inv.End(gentrail.InvocationEndParams{
//		Response:    response,
//		TotalTokens: inTok + outTok,
//	})
package gentrail
