import { randomUUID } from "node:crypto";

import {
  context,
  SpanStatusCode,
  trace,
  type Span,
  type Tracer,
  type TracerProvider,
} from "@opentelemetry/api";
import { BasicTracerProvider, BatchSpanProcessor } from "@opentelemetry/sdk-trace-base";

import {
  buildGentrailOtlpExporter,
  gentrailApiKeyFromEnv,
  redactionEnabledFromEnv,
} from "./otlpConfig.js";
import { redactPII } from "./pii.js";

export const GOVERNANCE_SOURCE = "aigentrail-sdk";
export const VALUE_CODE_POINTS_MAX = 4000;
export const INVOCATION_SPAN_NAME = "governance.invocation";
export const MODEL_CALL_SPAN_NAME = "governance.model_call";
const TRACER_NAME = "aigentrail.governance";

export interface FlushableTracerProvider extends TracerProvider {
  forceFlush(): Promise<void>;
  shutdown(): Promise<void>;
}

export interface GovernanceTracerOptions {
  tracerProvider: FlushableTracerProvider;
  redact?: boolean;
}

export interface InvocationStart {
  agentId: string;
  agentName: string;
  journalId: string;
  userMessage: string;
}

export interface InvocationEnd {
  response: string;
  totalTokens: number;
  toolCount: number;
  integrityHash: string;
  status?: string;
}

export interface ModelCall {
  modelId: string;
  prompt: string;
  responseText: string;
  inputTokens: number;
  outputTokens: number;
  latencyMs?: number;
}

export interface ToolCall {
  agentId: string;
  agentName: string;
  name: string;
  args: string;
  result: string;
  durationMs?: number;
  enforcedDecision?: string;
}

export interface LLMCall {
  agentId?: string;
  agentName?: string;
  journalId?: string;
  modelId: string;
  prompt: string;
  responseText: string;
  inputTokens?: number;
  outputTokens?: number;
  totalTokens?: number;
  latencyMs?: number;
  status?: string;
}

export interface InvocationHandle {
  readonly span: Span;
}

export type FetchFunction = (
  input: string | URL | Request,
  init?: RequestInit,
) => Promise<Response>;

export class GovernanceTracer {
  private readonly tracer: Tracer;
  private readonly tracerProvider: FlushableTracerProvider;
  private readonly redact: boolean;

  constructor(options: GovernanceTracerOptions) {
    this.tracerProvider = options.tracerProvider;
    this.tracer = options.tracerProvider.getTracer(TRACER_NAME);
    this.redact = options.redact ?? true;
  }

  startInvocation(start: InvocationStart): InvocationHandle {
    const span = this.tracer.startSpan(INVOCATION_SPAN_NAME, {}, context.active());
    span.setAttributes({
      "openinference.span.kind": "AGENT",
      "aigentrail.agent.id": start.agentId,
      "agent.name": start.agentName,
      "aigentrail.journal.id": start.journalId,
      "session.id": start.journalId,
      "input.value": this.attributeValue(start.userMessage),
      source: GOVERNANCE_SOURCE,
    });
    return { span };
  }

  endInvocation(handle: InvocationHandle, end: InvocationEnd): void {
    handle.span.setAttributes({
      "output.value": this.attributeValue(end.response),
      "aigentrail.invocation.status": end.status ?? "ok",
      "aigentrail.journal.integrity_hash": end.integrityHash,
      "llm.token_count.total": end.totalTokens,
      "aigentrail.tool.count": end.toolCount,
    });
    handle.span.setStatus({ code: SpanStatusCode.OK });
    handle.span.end();
  }

  recordModelCall(parent: InvocationHandle, call: ModelCall): void {
    const span = this.tracer.startSpan(
      MODEL_CALL_SPAN_NAME,
      {},
      trace.setSpan(context.active(), parent.span),
    );
    span.setAttributes({
      "openinference.span.kind": "LLM",
      "llm.model_name": call.modelId,
      "input.value": this.attributeValue(call.prompt),
      "output.value": this.attributeValue(call.responseText),
      "llm.token_count.prompt": call.inputTokens,
      "llm.token_count.completion": call.outputTokens,
    });
    if (call.latencyMs !== undefined) {
      span.setAttribute("aigentrail.latency_ms", call.latencyMs);
    }
    span.end();
  }

  recordToolCall(parent: InvocationHandle, call: ToolCall): void {
    const span = this.tracer.startSpan(call.name, {}, trace.setSpan(context.active(), parent.span));
    span.setAttributes({
      "openinference.span.kind": "TOOL",
      "tool.name": call.name,
      "aigentrail.agent.id": call.agentId,
      "agent.name": call.agentName,
      "input.value": this.attributeValue(call.args),
      "output.value": this.attributeValue(call.result),
    });
    if (call.durationMs !== undefined) {
      span.setAttribute("aigentrail.latency_ms", call.durationMs);
    }
    if (call.enforcedDecision) {
      span.setAttribute("aigentrail.enforcement.decision", call.enforcedDecision);
    }
    span.end();
  }

  recordLLMCall(call: LLMCall): void {
    const inputTokens = call.inputTokens ?? 0;
    const outputTokens = call.outputTokens ?? 0;
    const parent = this.startInvocation({
      agentId: call.agentId ?? "",
      agentName: call.agentName ?? "",
      journalId: call.journalId || randomUUID().replaceAll("-", ""),
      userMessage: call.prompt,
    });
    this.recordModelCall(parent, {
      modelId: call.modelId,
      prompt: call.prompt,
      responseText: call.responseText,
      inputTokens,
      outputTokens,
      latencyMs: call.latencyMs,
    });
    this.endInvocation(parent, {
      response: call.responseText,
      totalTokens: call.totalTokens ?? inputTokens + outputTokens,
      toolCount: 0,
      integrityHash: "",
      status: call.status,
    });
  }

  fetch(baseFetch: FetchFunction = globalThis.fetch): FetchFunction {
    return async (input, init) => {
      const startedAt = performance.now();
      const request = describeRequest(input, init);
      let status = "ok";
      try {
        const response = await baseFetch(input, init);
        if (response.status >= 400) {
          status = `http_${response.status}`;
        }
        return response;
      } catch (err) {
        status = "error";
        throw err;
      } finally {
        this.recordLLMCall({
          modelId: request.host,
          prompt: `${request.method} ${request.pathname}`,
          responseText: status,
          latencyMs: Math.floor(performance.now() - startedAt),
          status,
        });
      }
    };
  }

  forceFlush(): Promise<void> {
    return this.tracerProvider.forceFlush();
  }

  shutdown(): Promise<void> {
    return this.tracerProvider.shutdown();
  }

  private attributeValue(value: string): string {
    return truncateCodePoints(this.redact ? redactPII(value) : value, VALUE_CODE_POINTS_MAX);
  }
}

interface RequestDescription {
  method: string;
  host: string;
  pathname: string;
}

function describeRequest(
  input: string | URL | Request,
  init: RequestInit | undefined,
): RequestDescription {
  const isRequest = input instanceof Request;
  const rawUrl = isRequest ? input.url : String(input);
  const method = (init?.method ?? (isRequest ? input.method : "GET")).toUpperCase();
  if (!URL.canParse(rawUrl)) {
    return { method, host: "", pathname: rawUrl };
  }
  const url = new URL(rawUrl);
  return { method, host: url.host, pathname: url.pathname };
}

export function truncateCodePoints(value: string, codePointsMax: number): string {
  if (value.length <= codePointsMax) {
    return value;
  }
  let codePoints = 0;
  let index = 0;
  while (index < value.length && codePoints < codePointsMax) {
    const codePoint = value.codePointAt(index) ?? 0;
    index += codePoint > 0xffff ? 2 : 1;
    codePoints += 1;
  }
  return value.slice(0, index);
}

export interface CreateGovernanceTracerOptions {
  redact?: boolean;
}

export function createGovernanceTracer(
  options: CreateGovernanceTracerOptions = {},
): GovernanceTracer | null {
  const apiKey = gentrailApiKeyFromEnv();
  if (apiKey === "") {
    return null;
  }
  const exporter = buildGentrailOtlpExporter(apiKey);
  const tracerProvider = new BasicTracerProvider({
    spanProcessors: [new BatchSpanProcessor(exporter)],
  });
  return new GovernanceTracer({
    tracerProvider,
    redact: options.redact ?? redactionEnabledFromEnv(),
  });
}
