import assert from "node:assert/strict";
import test from "node:test";

import type { Attributes, Context } from "@opentelemetry/api";
import { ExportResultCode, type ExportResult } from "@opentelemetry/core";
import {
  BasicTracerProvider,
  InMemorySpanExporter,
  type ReadableSpan,
  type Span,
  type SpanProcessor,
} from "@opentelemetry/sdk-trace-base";

import {
  carriesGenAISignal,
  GENAI_SIGNAL_ATTRIBUTE_KEYS,
  GENAI_SIGNAL_ATTRIBUTE_PREFIXES,
  GenAISignalSpanExporter,
  instrument,
} from "../src/index.js";
import { readSpecJson, withEnv } from "./support.js";

interface ExportFilterSpec {
  export_filter: { attribute_prefixes: string[]; attribute_keys: string[] };
}

interface ExportFilterVector {
  name: string;
  attributes: Attributes;
  exported: boolean;
}

class ProviderAcceptingSpanProcessors {
  private readonly processors: SpanProcessor[] = [];
  private readonly provider: BasicTracerProvider;

  constructor() {
    const processors = this.processors;
    this.provider = new BasicTracerProvider({
      spanProcessors: [
        {
          onStart: (span: Span, parentContext: Context) =>
            processors.forEach((processor) => processor.onStart(span, parentContext)),
          onEnd: (span: ReadableSpan) => processors.forEach((processor) => processor.onEnd(span)),
          forceFlush: async () => {
            await Promise.all(processors.map((processor) => processor.forceFlush()));
          },
          shutdown: async () => {
            await Promise.all(processors.map((processor) => processor.shutdown()));
          },
        },
      ],
    });
  }

  addSpanProcessor(processor: SpanProcessor): void {
    this.processors.push(processor);
  }

  getTracer(name: string) {
    return this.provider.getTracer(name);
  }

  shutdown(): Promise<void> {
    return this.provider.shutdown();
  }
}

test("the export filter lists match spans.json", () => {
  const spec = readSpecJson("spans.json") as ExportFilterSpec;
  assert.deepEqual([...GENAI_SIGNAL_ATTRIBUTE_PREFIXES], spec.export_filter.attribute_prefixes);
  assert.deepEqual([...GENAI_SIGNAL_ATTRIBUTE_KEYS], spec.export_filter.attribute_keys);
});

test("carriesGenAISignal conforms to the shared export filter vectors", () => {
  const vectors = readSpecJson("export_filter_vectors.json") as ExportFilterVector[];
  assert.ok(vectors.length > 0, "export filter vectors are empty");
  for (const vector of vectors) {
    assert.equal(carriesGenAISignal(vector.attributes), vector.exported, vector.name);
  }
});

test("a batch with no GenAI span succeeds without reaching the wrapped exporter", () => {
  const wrapped = new InMemorySpanExporter();
  const results: ExportResult[] = [];
  new GenAISignalSpanExporter(wrapped).export([], (result) => results.push(result));
  assert.deepEqual(results, [{ code: ExportResultCode.SUCCESS }]);
  assert.equal(wrapped.getFinishedSpans().length, 0);
});

for (const redact of [true, false]) {
  test(`instrument exports GenAI spans and drops app spans (redact ${redact})`, async () => {
    await withEnv({ GENTRAIL_API_KEY: "sk-test" }, async () => {
      const provider = new ProviderAcceptingSpanProcessors();
      const exporter = new InMemorySpanExporter();
      const processor = instrument(provider, { exporter, redact });
      assert.ok(processor !== null);
      const chat = provider.getTracer("app").startSpan("chat");
      chat.setAttributes({ "gen_ai.operation.name": "chat", "input.value": "hi" });
      chat.end();
      const query = provider.getTracer("app").startSpan("SELECT users");
      query.setAttributes({
        "db.system": "postgresql",
        "db.statement": "SELECT * FROM users WHERE email='jane.doe@example.com'",
      });
      query.end();
      const inputOnly = provider.getTracer("app").startSpan("render");
      inputOnly.setAttribute("input.value", "mail jane.doe@example.com");
      inputOnly.end();
      await processor.forceFlush();
      assert.deepEqual(
        exporter.getFinishedSpans().map((span) => span.name),
        ["chat"],
      );
      await provider.shutdown();
    });
  });
}
