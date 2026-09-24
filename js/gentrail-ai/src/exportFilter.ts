import type { Attributes } from "@opentelemetry/api";
import { ExportResultCode } from "@opentelemetry/core";
import type { ReadableSpan, SpanExporter } from "@opentelemetry/sdk-trace-base";

export const GENAI_SIGNAL_ATTRIBUTE_PREFIXES = [
  "gen_ai.",
  "ai.",
  "llm.",
  "openinference.",
  "aigentrail.",
] as const;
export const GENAI_SIGNAL_ATTRIBUTE_KEYS = ["session.id", "agent.name", "tool.name"] as const;

const GENAI_SIGNAL_ATTRIBUTE_KEY_SET: ReadonlySet<string> = new Set(GENAI_SIGNAL_ATTRIBUTE_KEYS);

type ExportResultCallback = Parameters<SpanExporter["export"]>[1];

export function carriesGenAISignal(attributes: Attributes): boolean {
  for (const key of Object.keys(attributes)) {
    if (GENAI_SIGNAL_ATTRIBUTE_KEY_SET.has(key)) {
      return true;
    }
    if (GENAI_SIGNAL_ATTRIBUTE_PREFIXES.some((prefix) => key.startsWith(prefix))) {
      return true;
    }
  }
  return false;
}

export class GenAISignalSpanExporter implements SpanExporter {
  private readonly wrapped: SpanExporter;

  constructor(wrapped: SpanExporter) {
    this.wrapped = wrapped;
  }

  export(spans: ReadableSpan[], resultCallback: ExportResultCallback): void {
    const spansWithGenAISignal = spans.filter((span) => carriesGenAISignal(span.attributes));
    if (spansWithGenAISignal.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }
    this.wrapped.export(spansWithGenAISignal, resultCallback);
  }

  shutdown(): Promise<void> {
    return this.wrapped.shutdown();
  }

  forceFlush(): Promise<void> {
    return this.wrapped.forceFlush?.() ?? Promise.resolve();
  }
}
