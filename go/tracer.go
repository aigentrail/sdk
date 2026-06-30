package gentrail

import (
	"context"
	"crypto/rand"
	"encoding/hex"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

const (
	invocationSpanName = "governance.invocation"
	modelCallSpanName  = "governance.model_call"
	sourceAttrValue    = "aigentrail-sdk"

	maxInputValueRunes  = 4000
	maxOutputValueRunes = 4000
	maxModelOutputRunes = 4000
)

// Tracer emits governance spans (invocations, model calls, tool calls) over
// OTLP. Construct one per process with New; call Shutdown before exit.
type Tracer struct {
	tracer   trace.Tracer
	provider *sdktrace.TracerProvider
}

// InvocationParams describes a new agent invocation that wraps a sequence of
// model and tool calls.
type InvocationParams struct {
	AgentID     string
	AgentName   string
	JournalID   string
	UserMessage string
}

// InvocationEndParams describes the outcome of an invocation. An empty Status
// is treated as "ok".
type InvocationEndParams struct {
	Response      string
	TotalTokens   int64
	ToolCount     int64
	IntegrityHash string
	Status        string
}

// ModelCallParams describes a single LLM call inside an invocation. A zero
// LatencyMS is omitted from the span.
type ModelCallParams struct {
	ModelID      string
	Prompt       string
	ResponseText string
	InputTokens  int64
	OutputTokens int64
	LatencyMS    float64
}

// ToolCallParams describes a single tool invocation inside an agent
// invocation. A zero DurationMS is omitted from the span.
type ToolCallParams struct {
	AgentID    string
	AgentName  string
	Name       string
	Args       string
	Result     string
	DurationMS float64
}

// LLMCallParams describes a single standalone LLM call for RecordLLMCall.
// JournalID is generated when empty; Status defaults to "ok".
type LLMCallParams struct {
	AgentID      string
	AgentName    string
	JournalID    string
	ModelID      string
	Prompt       string
	Response     string
	InputTokens  int64
	OutputTokens int64
	LatencyMS    float64
	Status       string
}

// Invocation is a handle to an in-flight governance.invocation span. Call End
// exactly once. The context returned by StartInvocation must be passed to
// RecordModelCall and RecordToolCall so they nest correctly.
type Invocation struct {
	span trace.Span
}

// StartInvocation opens a governance.invocation span and returns a context
// scoped to it. Pass that context to RecordModelCall / RecordToolCall so
// child spans nest correctly. JournalID is generated when empty. A nil Tracer
// is a no-op and returns ctx unchanged with a nil Invocation.
func (t *Tracer) StartInvocation(ctx context.Context, p InvocationParams) (context.Context, *Invocation) {
	if t == nil {
		return ctx, nil
	}
	if p.JournalID == "" {
		p.JournalID = newJournalID()
	}
	ctx, span := t.tracer.Start(ctx, invocationSpanName)
	span.SetAttributes(
		attribute.String("openinference.span.kind", "AGENT"),
		attribute.String("aigentrail.agent.id", p.AgentID),
		attribute.String("agent.name", p.AgentName),
		attribute.String("aigentrail.journal.id", p.JournalID),
		attribute.String("session.id", p.JournalID),
		attribute.String("input.value", truncateRunes(p.UserMessage, maxInputValueRunes)),
		attribute.String("source", sourceAttrValue),
	)
	return ctx, &Invocation{span: span}
}

// End closes the invocation span. Status defaults to "ok" if empty. A nil
// Invocation is a no-op.
func (i *Invocation) End(p InvocationEndParams) {
	if i == nil {
		return
	}
	status := p.Status
	if status == "" {
		status = "ok"
	}
	i.span.SetAttributes(
		attribute.String("output.value", truncateRunes(p.Response, maxOutputValueRunes)),
		attribute.String("aigentrail.invocation.status", status),
		attribute.String("aigentrail.journal.integrity_hash", p.IntegrityHash),
		attribute.Int64("llm.token_count.total", p.TotalTokens),
		attribute.Int64("aigentrail.tool.count", p.ToolCount),
	)
	i.span.SetStatus(codes.Ok, "")
	i.span.End()
}

// RecordModelCall emits a governance.model_call span as a child of whatever
// span is in ctx (typically the invocation returned by StartInvocation). A nil
// Tracer is a no-op.
func (t *Tracer) RecordModelCall(ctx context.Context, p ModelCallParams) {
	if t == nil {
		return
	}
	_, span := t.tracer.Start(ctx, modelCallSpanName)
	defer span.End()
	span.SetAttributes(
		attribute.String("openinference.span.kind", "LLM"),
		attribute.String("llm.model_name", p.ModelID),
		attribute.String("input.value", truncateRunes(p.Prompt, maxInputValueRunes)),
		attribute.String("output.value", truncateRunes(p.ResponseText, maxModelOutputRunes)),
		attribute.Int64("llm.token_count.prompt", p.InputTokens),
		attribute.Int64("llm.token_count.completion", p.OutputTokens),
	)
	if p.LatencyMS > 0 {
		span.SetAttributes(attribute.Float64("aigentrail.latency_ms", p.LatencyMS))
	}
}

// RecordToolCall emits a tool-call span (named after the tool) as a child of
// whatever span is in ctx. The agent.id / agent.name attributes let the
// collector re-attach tool calls to their parent invocation even when the
// BatchSpanProcessor flushes children before the parent ends.
func (t *Tracer) RecordToolCall(ctx context.Context, p ToolCallParams) {
	if t == nil {
		return
	}
	_, span := t.tracer.Start(ctx, p.Name)
	defer span.End()
	span.SetAttributes(
		attribute.String("openinference.span.kind", "TOOL"),
		attribute.String("tool.name", p.Name),
		attribute.String("aigentrail.agent.id", p.AgentID),
		attribute.String("agent.name", p.AgentName),
		attribute.String("input.value", truncateRunes(p.Args, maxInputValueRunes)),
		attribute.String("output.value", truncateRunes(p.Result, maxOutputValueRunes)),
	)
	if p.DurationMS > 0 {
		span.SetAttributes(attribute.Float64("aigentrail.latency_ms", p.DurationMS))
	}
}

// RecordLLMCall opens an invocation, records one model call, and ends the
// invocation in a single call. A nil Tracer is a no-op.
func (t *Tracer) RecordLLMCall(ctx context.Context, p LLMCallParams) {
	if t == nil {
		return
	}
	ctx, invocation := t.StartInvocation(ctx, InvocationParams{
		AgentID:     p.AgentID,
		AgentName:   p.AgentName,
		JournalID:   p.JournalID,
		UserMessage: p.Prompt,
	})
	t.RecordModelCall(ctx, ModelCallParams{
		ModelID:      p.ModelID,
		Prompt:       p.Prompt,
		ResponseText: p.Response,
		InputTokens:  p.InputTokens,
		OutputTokens: p.OutputTokens,
		LatencyMS:    p.LatencyMS,
	})
	invocation.End(InvocationEndParams{
		Response:    p.Response,
		TotalTokens: p.InputTokens + p.OutputTokens,
		Status:      p.Status,
	})
}

func newJournalID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(b[:])
}

func truncateRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= n {
		return s
	}
	return string(runes[:n])
}
