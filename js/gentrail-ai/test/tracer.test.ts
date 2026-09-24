import assert from "node:assert/strict";
import test from "node:test";

import {
  BasicTracerProvider,
  InMemorySpanExporter,
  SimpleSpanProcessor,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-base";

import { createGovernanceTracer, GovernanceTracer } from "../src/index.js";
import { readSpecJson, serve, withEnv } from "./support.js";

interface SpanSpec {
  name: string;
  span_kind: string;
  start_attributes?: string[];
  end_attributes?: string[];
  attributes?: string[];
  optional_attributes?: string[];
}

interface SpansSpec {
  source: string;
  value_rune_limit: number;
  enforcement_decision_attribute: string;
  invocation: SpanSpec;
  model_call: SpanSpec;
  tool_call: SpanSpec;
}

const spansSpec = readSpecJson("spans.json") as SpansSpec;

function inMemoryTracer(redact = true): {
  tracer: GovernanceTracer;
  exporter: InMemorySpanExporter;
} {
  const exporter = new InMemorySpanExporter();
  const tracerProvider = new BasicTracerProvider({
    spanProcessors: [new SimpleSpanProcessor(exporter)],
  });
  return { tracer: new GovernanceTracer({ tracerProvider, redact }), exporter };
}

function spanNamed(spans: ReadableSpan[], name: string): ReadableSpan {
  const span = spans.find((candidate) => candidate.name === name);
  assert.ok(span !== undefined, `no span named ${name}`);
  return span;
}

function assertAttributesPresent(span: ReadableSpan, keys: readonly string[]): void {
  for (const key of keys) {
    assert.ok(key in span.attributes, `${span.name} is missing ${key}`);
  }
}

function assertChildOf(child: ReadableSpan, parent: ReadableSpan): void {
  assert.equal(child.parentSpanContext?.spanId, parent.spanContext().spanId);
  assert.equal(child.spanContext().traceId, parent.spanContext().traceId);
}

function recordFullInvocation(tracer: GovernanceTracer, enforcedDecision?: string): void {
  const invocation = tracer.startInvocation({
    agentId: "agent-billing",
    agentName: "Billing Agent",
    journalId: "inv-1",
    userMessage: "refund jane@acme.com",
  });
  tracer.recordModelCall(invocation, {
    modelId: "claude-sonnet",
    prompt: "refund jane@acme.com",
    responseText: "calling issue_refund",
    inputTokens: 120,
    outputTokens: 48,
    latencyMs: 812.25,
  });
  tracer.recordToolCall(invocation, {
    agentId: "agent-billing",
    agentName: "Billing Agent",
    name: "issue_refund",
    args: '{"ssn":"123-45-6789"}',
    result: "ok",
    durationMs: 41.5,
    enforcedDecision,
  });
  tracer.endInvocation(invocation, {
    response: "Refund issued.",
    totalTokens: 168,
    toolCount: 1,
    integrityHash: "abc",
  });
}

test("governance spans carry every attribute pinned by spans.json", () => {
  const { tracer, exporter } = inMemoryTracer();
  recordFullInvocation(tracer, "BLOCK");
  const spans = exporter.getFinishedSpans();
  const invocation = spanNamed(spans, spansSpec.invocation.name);
  const modelCall = spanNamed(spans, spansSpec.model_call.name);
  const toolCall = spanNamed(spans, "issue_refund");
  assertAttributesPresent(invocation, [
    ...(spansSpec.invocation.start_attributes ?? []),
    ...(spansSpec.invocation.end_attributes ?? []),
  ]);
  assertAttributesPresent(modelCall, [
    ...(spansSpec.model_call.attributes ?? []),
    ...(spansSpec.model_call.optional_attributes ?? []),
  ]);
  assertAttributesPresent(toolCall, [
    ...(spansSpec.tool_call.attributes ?? []),
    ...(spansSpec.tool_call.optional_attributes ?? []),
  ]);
  assert.equal(invocation.attributes["openinference.span.kind"], spansSpec.invocation.span_kind);
  assert.equal(modelCall.attributes["openinference.span.kind"], spansSpec.model_call.span_kind);
  assert.equal(toolCall.attributes["openinference.span.kind"], spansSpec.tool_call.span_kind);
  assert.equal(invocation.attributes.source, spansSpec.source);
  assert.equal(invocation.attributes["session.id"], "inv-1");
  assert.equal(invocation.attributes["aigentrail.invocation.status"], "ok");
  assert.equal(toolCall.attributes["tool.name"], "issue_refund");
  assert.equal(toolCall.attributes[spansSpec.enforcement_decision_attribute], "BLOCK");
  assert.equal(modelCall.attributes["aigentrail.latency_ms"], 812.25);
  assertChildOf(modelCall, invocation);
  assertChildOf(toolCall, invocation);
  assert.equal(invocation.parentSpanContext, undefined);
});

test("optional attributes are omitted when not supplied", () => {
  const { tracer, exporter } = inMemoryTracer();
  const invocation = tracer.startInvocation({
    agentId: "a",
    agentName: "A",
    journalId: "j",
    userMessage: "",
  });
  tracer.recordModelCall(invocation, {
    modelId: "m",
    prompt: "",
    responseText: "",
    inputTokens: 0,
    outputTokens: 0,
  });
  tracer.recordToolCall(invocation, {
    agentId: "a",
    agentName: "A",
    name: "t",
    args: "",
    result: "",
  });
  tracer.endInvocation(invocation, {
    response: "",
    totalTokens: 0,
    toolCount: 1,
    integrityHash: "",
    status: "error",
  });
  const spans = exporter.getFinishedSpans();
  assert.equal(
    "aigentrail.latency_ms" in spanNamed(spans, spansSpec.model_call.name).attributes,
    false,
  );
  assert.equal("aigentrail.latency_ms" in spanNamed(spans, "t").attributes, false);
  assert.equal(spansSpec.enforcement_decision_attribute in spanNamed(spans, "t").attributes, false);
  assert.equal(
    spanNamed(spans, spansSpec.invocation.name).attributes["aigentrail.invocation.status"],
    "error",
  );
});

test("values are redacted unless disabled", () => {
  const redacting = inMemoryTracer(true);
  recordFullInvocation(redacting.tracer);
  const redactedSpans = redacting.exporter.getFinishedSpans();
  assert.equal(
    spanNamed(redactedSpans, spansSpec.invocation.name).attributes["input.value"],
    "refund [EMAIL]",
  );
  assert.equal(
    spanNamed(redactedSpans, "issue_refund").attributes["input.value"],
    '{"ssn":"[SSN]"}',
  );
  const raw = inMemoryTracer(false);
  recordFullInvocation(raw.tracer);
  assert.equal(
    spanNamed(raw.exporter.getFinishedSpans(), spansSpec.invocation.name).attributes["input.value"],
    "refund jane@acme.com",
  );
});

test("values are truncated to the code point limit after redaction", () => {
  const { tracer, exporter } = inMemoryTracer();
  const limit = spansSpec.value_rune_limit;
  const astral = "\u{1F600}".repeat(limit + 10);
  const invocation = tracer.startInvocation({
    agentId: "a",
    agentName: "A",
    journalId: "j",
    userMessage: astral,
  });
  tracer.endInvocation(invocation, {
    response: "x".repeat(limit - 2) + " a@b.com",
    totalTokens: 0,
    toolCount: 0,
    integrityHash: "",
  });
  const span = spanNamed(exporter.getFinishedSpans(), spansSpec.invocation.name);
  const input = String(span.attributes["input.value"]);
  assert.equal([...input].length, limit);
  assert.equal(input, "\u{1F600}".repeat(limit));
  assert.equal(span.attributes["output.value"], "x".repeat(limit - 2) + " [");
});

test("recordLLMCall emits a closed invocation with one model call", () => {
  const { tracer, exporter } = inMemoryTracer();
  tracer.recordLLMCall({
    modelId: "gpt",
    prompt: "hi",
    responseText: "hello",
    inputTokens: 3,
    outputTokens: 4,
  });
  const spans = exporter.getFinishedSpans();
  assert.equal(spans.length, 2);
  const invocation = spanNamed(spans, spansSpec.invocation.name);
  assertChildOf(spanNamed(spans, spansSpec.model_call.name), invocation);
  assert.match(String(invocation.attributes["aigentrail.journal.id"]), /^[0-9a-f]{32}$/);
  assert.equal(invocation.attributes["llm.token_count.total"], 7);
  assert.equal(invocation.attributes["aigentrail.tool.count"], 0);
});

test("fetch records one LLM call per request with its status", async () => {
  const srv = await serve((req) =>
    req.url === "/v1/fail" ? { status: 503 } : { json: { ok: true } },
  );
  try {
    const { tracer, exporter } = inMemoryTracer();
    const tracedFetch = tracer.fetch();
    const ok = await tracedFetch(`${srv.base}/v1/messages?x=1`, { method: "post", body: "{}" });
    assert.equal(ok.status, 200);
    const failed = await tracedFetch(new Request(`${srv.base}/v1/fail`));
    assert.equal(failed.status, 503);
    await assert.rejects(tracedFetch("http://127.0.0.1:9/v1/down"));
    const modelCalls = exporter
      .getFinishedSpans()
      .filter((span) => span.name === spansSpec.model_call.name);
    const host = new URL(srv.base).host;
    assert.deepEqual(
      modelCalls.map((span) => [
        span.attributes["llm.model_name"],
        span.attributes["input.value"],
        span.attributes["output.value"],
      ]),
      [
        [host, "POST /v1/messages", "ok"],
        [host, "GET /v1/fail", "http_503"],
        ["127.0.0.1:9", "GET /v1/down", "error"],
      ],
    );
    for (const span of modelCalls) {
      assert.ok(Number.isInteger(span.attributes["aigentrail.latency_ms"]));
    }
    const statuses = exporter
      .getFinishedSpans()
      .filter((span) => span.name === spansSpec.invocation.name)
      .map((span) => span.attributes["aigentrail.invocation.status"]);
    assert.deepEqual(statuses, ["ok", "http_503", "error"]);
  } finally {
    await srv.close();
  }
});

test("createGovernanceTracer stays off without GENTRAIL_API_KEY and warns when half configured", async (t) => {
  const warn = t.mock.method(console, "warn", () => undefined);
  await withEnv(
    {
      GENTRAIL_API_KEY: undefined,
      AIGENTRAIL_API_KEY: undefined,
      OTEL_EXPORTER_OTLP_ENDPOINT: undefined,
    },
    () => {
      assert.equal(createGovernanceTracer(), null);
    },
  );
  assert.equal(warn.mock.callCount(), 0);
  await withEnv(
    {
      GENTRAIL_API_KEY: undefined,
      AIGENTRAIL_API_KEY: "old",
      OTEL_EXPORTER_OTLP_ENDPOINT: undefined,
    },
    () => {
      assert.equal(createGovernanceTracer(), null);
    },
  );
  await withEnv(
    {
      GENTRAIL_API_KEY: undefined,
      AIGENTRAIL_API_KEY: undefined,
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://x",
    },
    () => {
      assert.equal(createGovernanceTracer(), null);
    },
  );
  assert.equal(warn.mock.callCount(), 2);
});

async function exportOnceFromEnv(
  env: Record<string, string | undefined>,
): Promise<{ url: string; auth: string | undefined }> {
  const srv = await serve(() => ({ json: {} }));
  try {
    return await withEnv({ ...env, OTEL_EXPORTER_OTLP_ENDPOINT: srv.base + "/" }, async () => {
      const tracer = createGovernanceTracer();
      assert.ok(tracer !== null);
      tracer.recordLLMCall({ modelId: "m", prompt: "p", responseText: "r" });
      await tracer.shutdown();
      assert.equal(srv.requests.length, 1);
      return { url: srv.requests[0].url, auth: srv.requests[0].auth };
    });
  } finally {
    await srv.close();
  }
}

test("createGovernanceTracer exports to the configured endpoint with Bearer auth", async () => {
  const seen = await exportOnceFromEnv({
    GENTRAIL_API_KEY: "sk-env",
    OTEL_EXPORTER_OTLP_HEADERS: undefined,
    OTEL_EXPORTER_OTLP_TRACES_HEADERS: undefined,
  });
  assert.deepEqual(seen, { url: "/v1/traces", auth: "Bearer sk-env" });
});

test("standard OTLP header variables replace the Bearer header", async () => {
  const seen = await exportOnceFromEnv({
    GENTRAIL_API_KEY: "sk-env",
    OTEL_EXPORTER_OTLP_HEADERS: "authorization=Custom abc",
    OTEL_EXPORTER_OTLP_TRACES_HEADERS: undefined,
  });
  assert.deepEqual(seen, { url: "/v1/traces", auth: "Custom abc" });
});
