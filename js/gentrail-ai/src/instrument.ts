import {
  context,
  ProxyTracerProvider,
  trace,
  type AttributeValue,
  type Attributes,
  type Context,
  type TracerProvider,
} from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";
import {
  BasicTracerProvider,
  BatchSpanProcessor,
  type ReadableSpan,
  type Span,
  type SpanExporter,
  type SpanProcessor,
} from "@opentelemetry/sdk-trace-base";

import { GenAISignalSpanExporter } from "./exportFilter.js";
import {
  buildGentrailOtlpExporter,
  gentrailApiKeyFromEnv,
  redactionEnabledFromEnv,
} from "./otlpConfig.js";
import { redactPII } from "./pii.js";

export const REDACTED_ATTRIBUTE_PREFIXES = ["gen_ai.", "ai.", "input.", "output."] as const;
export const REDACTION_APPLIED_ATTRIBUTE = "aigentrail.redaction.applied";

type ExportResultCallback = Parameters<SpanExporter["export"]>[1];

export class RedactingSpanExporter implements SpanExporter {
  private readonly wrapped: SpanExporter;

  constructor(wrapped: SpanExporter) {
    this.wrapped = wrapped;
  }

  export(spans: ReadableSpan[], resultCallback: ExportResultCallback): void {
    this.wrapped.export(spans.map(redactedSpanCopy), resultCallback);
  }

  shutdown(): Promise<void> {
    return this.wrapped.shutdown();
  }

  forceFlush(): Promise<void> {
    return this.wrapped.forceFlush?.() ?? Promise.resolve();
  }
}

export function redactedSpanCopy(span: ReadableSpan): ReadableSpan {
  const replaced = redactedAttributes(span.attributes);
  if (replaced === null) {
    return span;
  }
  return {
    name: span.name,
    kind: span.kind,
    spanContext: () => span.spanContext(),
    parentSpanContext: span.parentSpanContext,
    startTime: span.startTime,
    endTime: span.endTime,
    status: span.status,
    attributes: { ...span.attributes, ...replaced, [REDACTION_APPLIED_ATTRIBUTE]: true },
    links: span.links,
    events: span.events,
    duration: span.duration,
    ended: span.ended,
    resource: span.resource,
    instrumentationScope: span.instrumentationScope,
    droppedAttributesCount: span.droppedAttributesCount,
    droppedEventsCount: span.droppedEventsCount,
    droppedLinksCount: span.droppedLinksCount,
  };
}

function redactedAttributes(attributes: Attributes): Attributes | null {
  const replaced: Attributes = {};
  let changed = false;
  for (const [key, value] of Object.entries(attributes)) {
    if (
      value === undefined ||
      !REDACTED_ATTRIBUTE_PREFIXES.some((prefix) => key.startsWith(prefix))
    ) {
      continue;
    }
    const redacted = redactedAttributeValue(value);
    if (redacted !== null) {
      replaced[key] = redacted;
      changed = true;
    }
  }
  return changed ? replaced : null;
}

function redactedAttributeValue(value: AttributeValue): AttributeValue | null {
  if (typeof value === "string") {
    const redacted = redactPII(value);
    return redacted === value ? null : redacted;
  }
  if (!Array.isArray(value) || !value.some((item) => typeof item === "string")) {
    return null;
  }
  const items = value as readonly (string | null | undefined)[];
  const redacted = items.map((item) => (typeof item === "string" ? redactPII(item) : item));
  return redacted.some((item, index) => item !== items[index]) ? redacted : null;
}

export interface GentrailSpanProcessorOptions {
  exporter?: SpanExporter;
  redact?: boolean;
}

export class GentrailSpanProcessor implements SpanProcessor {
  private readonly batch: BatchSpanProcessor;

  constructor(options: GentrailSpanProcessorOptions = {}) {
    const exporter = options.exporter ?? defaultGentrailExporter();
    const redact = options.redact ?? redactionEnabledFromEnv();
    const redactingOrRaw = redact ? new RedactingSpanExporter(exporter) : exporter;
    this.batch = new BatchSpanProcessor(new GenAISignalSpanExporter(redactingOrRaw));
  }

  onStart(span: Span, parentContext: Context): void {
    this.batch.onStart(span, parentContext);
  }

  onEnd(span: ReadableSpan): void {
    this.batch.onEnd(span);
  }

  forceFlush(): Promise<void> {
    return this.batch.forceFlush();
  }

  shutdown(): Promise<void> {
    return this.batch.shutdown();
  }
}

function defaultGentrailExporter(): SpanExporter {
  const apiKey = gentrailApiKeyFromEnv();
  if (apiKey === "") {
    throw new Error("GentrailSpanProcessor requires GENTRAIL_API_KEY");
  }
  return buildGentrailOtlpExporter(apiKey);
}

interface SpanProcessorHost {
  addSpanProcessor(processor: SpanProcessor): void;
}

function acceptsSpanProcessors(
  provider: TracerProvider,
): provider is TracerProvider & SpanProcessorHost {
  return typeof (provider as Partial<SpanProcessorHost>).addSpanProcessor === "function";
}

export function instrument(
  provider?: TracerProvider,
  options: GentrailSpanProcessorOptions = {},
): GentrailSpanProcessor | null {
  if (gentrailApiKeyFromEnv() === "") {
    return null;
  }
  const processor = processorOrNull(options);
  if (processor === null) {
    return null;
  }
  if (provider !== undefined) {
    attachToProvider(provider, processor);
    return processor;
  }
  if (installGlobalProvider(processor)) {
    return processor;
  }
  const global = trace.getTracerProvider();
  attachToProvider(
    global instanceof ProxyTracerProvider ? global.getDelegate() : global,
    processor,
  );
  return processor;
}

function processorOrNull(options: GentrailSpanProcessorOptions): GentrailSpanProcessor | null {
  try {
    return new GentrailSpanProcessor(options);
  } catch (err) {
    console.warn(`gentrail: span export disabled (${String(err)})`);
    return null;
  }
}

function attachToProvider(provider: TracerProvider, processor: SpanProcessor): void {
  if (acceptsSpanProcessors(provider)) {
    provider.addSpanProcessor(processor);
    return;
  }
  console.warn(
    "gentrail: this TracerProvider cannot accept span processors after construction; " +
      "pass the returned GentrailSpanProcessor in its spanProcessors option",
  );
}

function installGlobalProvider(processor: SpanProcessor): boolean {
  const provider = new BasicTracerProvider({ spanProcessors: [processor] });
  if (!trace.setGlobalTracerProvider(provider)) {
    return false;
  }
  const contextManager = new AsyncLocalStorageContextManager().enable();
  if (!context.setGlobalContextManager(contextManager)) {
    contextManager.disable();
  }
  return true;
}
