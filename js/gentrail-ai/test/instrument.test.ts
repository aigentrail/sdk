import assert from "node:assert/strict";
import test from "node:test";

import { trace, type TracerProvider } from "@opentelemetry/api";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  type ReadableSpan,
  type SpanProcessor,
} from "@opentelemetry/sdk-trace-base";

import {
  GentrailSpanProcessor,
  instrument,
  REDACTED_ATTRIBUTE_PREFIXES,
  REDACTION_APPLIED_ATTRIBUTE,
} from "../src/index.js";
import { readSpecJson, withEnv } from "./support.js";

interface SpansSpec {
  redacted_attribute_prefixes: string[];
  redaction_applied_attribute: string;
}

const spansSpec = readSpecJson("spans.json") as SpansSpec;

class AppSpanRecorder implements SpanProcessor {
  readonly spans: ReadableSpan[] = [];

  onStart(): void {}

  onEnd(span: ReadableSpan): void {
    this.spans.push(span);
  }

  forceFlush(): Promise<void> {
    return Promise.resolve();
  }

  shutdown(): Promise<void> {
    return Promise.resolve();
  }
}

test("redaction prefixes and stamp match spans.json", () => {
  assert.deepEqual([...REDACTED_ATTRIBUTE_PREFIXES], spansSpec.redacted_attribute_prefixes);
  assert.equal(REDACTION_APPLIED_ATTRIBUTE, spansSpec.redaction_applied_attribute);
});

test("the processor redacts a copy on export and leaves the app's span raw", async () => {
  const gentrailExporter = new InMemorySpanExporter();
  const appRecorder = new AppSpanRecorder();
  const provider = new BasicTracerProvider({
    spanProcessors: [
      new GentrailSpanProcessor({ exporter: gentrailExporter, redact: true }),
      appRecorder,
    ],
  });
  const span = provider.getTracer("app").startSpan("chat");
  span.setAttributes({
    "gen_ai.prompt": "mail jane@acme.com",
    "ai.response.messages": ["ssn 123-45-6789", "fine"],
    "input.value": "nothing here",
    "user.email": "jane@acme.com",
    "output.value": 42,
  });
  span.end();
  const clean = provider.getTracer("app").startSpan("clean");
  clean.setAttribute("gen_ai.prompt", "hello");
  clean.end();
  await provider.forceFlush();

  const [exported, exportedClean] = gentrailExporter.getFinishedSpans();
  assert.equal(exported.attributes["gen_ai.prompt"], "mail [EMAIL]");
  assert.deepEqual(exported.attributes["ai.response.messages"], ["ssn [SSN]", "fine"]);
  assert.equal(exported.attributes["input.value"], "nothing here");
  assert.equal(exported.attributes["user.email"], "jane@acme.com");
  assert.equal(exported.attributes["output.value"], 42);
  assert.equal(exported.attributes[REDACTION_APPLIED_ATTRIBUTE], true);
  assert.equal(exported.spanContext().spanId, span.spanContext().spanId);
  assert.equal(REDACTION_APPLIED_ATTRIBUTE in exportedClean.attributes, false);

  const [appSpan] = appRecorder.spans;
  assert.equal(appSpan.attributes["gen_ai.prompt"], "mail jane@acme.com");
  assert.equal(REDACTION_APPLIED_ATTRIBUTE in appSpan.attributes, false);
  await provider.shutdown();
});

test("the processor exports raw spans when redaction is disabled", async () => {
  const gentrailExporter = new InMemorySpanExporter();
  const provider = new BasicTracerProvider({
    spanProcessors: [new GentrailSpanProcessor({ exporter: gentrailExporter, redact: false })],
  });
  const span = provider.getTracer("app").startSpan("chat");
  span.setAttribute("gen_ai.prompt", "mail jane@acme.com");
  span.end();
  await provider.forceFlush();
  assert.equal(
    gentrailExporter.getFinishedSpans()[0].attributes["gen_ai.prompt"],
    "mail jane@acme.com",
  );
  await provider.shutdown();
});

test("instrument is off without GENTRAIL_API_KEY", async () => {
  await withEnv(
    {
      GENTRAIL_API_KEY: undefined,
      AIGENTRAIL_API_KEY: undefined,
      OTEL_EXPORTER_OTLP_ENDPOINT: undefined,
    },
    () => {
      assert.equal(instrument(), null);
    },
  );
});

test("instrument attaches to a provider that accepts span processors", async () => {
  await withEnv({ GENTRAIL_API_KEY: "sk-test" }, async () => {
    const attached: SpanProcessor[] = [];
    const provider = {
      getTracer: () => {
        throw new Error("unused");
      },
      addSpanProcessor: (processor: SpanProcessor) => attached.push(processor),
    } as TracerProvider & { addSpanProcessor(processor: SpanProcessor): void };
    const exporter = new InMemorySpanExporter();
    const processor = instrument(provider, { exporter });
    assert.ok(processor instanceof GentrailSpanProcessor);
    assert.deepEqual(attached, [processor]);
    await processor.shutdown();
  });
});

test("instrument installs a global provider when the app has none", async () => {
  await withEnv({ GENTRAIL_API_KEY: "sk-test" }, async () => {
    const exporter = new InMemorySpanExporter();
    const processor = instrument(undefined, { exporter });
    assert.ok(processor !== null);
    const span = trace.getTracer("app").startSpan("chat");
    span.setAttribute("gen_ai.prompt", "reach +44 20 7946 0958");
    span.end();
    await processor.forceFlush();
    const [exported] = exporter.getFinishedSpans();
    assert.equal(exported.attributes["gen_ai.prompt"], "reach [PHONE]");
    await processor.shutdown();
  });
});
