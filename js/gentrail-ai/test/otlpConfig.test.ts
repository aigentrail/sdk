import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { init, instrument, otlpExporterConfigFromEnv } from "../src/index.js";
import { withEnv } from "./support.js";

const PEM = "-----BEGIN CERTIFICATE-----\nMIIBfake\n-----END CERTIFICATE-----\n";
const TLS_UNSET = {
  OTEL_EXPORTER_OTLP_CERTIFICATE: undefined,
  OTEL_EXPORTER_OTLP_INSECURE: undefined,
  OTEL_EXPORTER_OTLP_HEADERS: undefined,
  OTEL_EXPORTER_OTLP_TRACES_HEADERS: undefined,
  OTEL_EXPORTER_OTLP_ENDPOINT: undefined,
};

function writeCertificate(): string {
  const path = join(mkdtempSync(join(tmpdir(), "gentrail-ca-")), "ca.pem");
  writeFileSync(path, PEM);
  return path;
}

test("the exporter config has no agent options when TLS is not configured", async () => {
  await withEnv(TLS_UNSET, () => {
    assert.deepEqual(otlpExporterConfigFromEnv("sk-test"), {
      url: "https://otel.gentrail.ai/v1/traces",
      headers: { Authorization: "Bearer sk-test" },
    });
  });
});

test("OTEL_EXPORTER_OTLP_CERTIFICATE is trusted as the CA", async () => {
  await withEnv({ ...TLS_UNSET, OTEL_EXPORTER_OTLP_CERTIFICATE: writeCertificate() }, () => {
    const options = otlpExporterConfigFromEnv("sk-test").httpAgentOptions;
    assert.equal(options?.ca?.toString(), PEM);
    assert.equal(options?.rejectUnauthorized, undefined);
    assert.equal(options?.keepAlive, true);
  });
});

test("OTEL_EXPORTER_OTLP_INSECURE skips certificate verification without changing the scheme", async () => {
  for (const value of ["true", "TRUE", "1", "yes", "Yes"]) {
    await withEnv({ ...TLS_UNSET, OTEL_EXPORTER_OTLP_INSECURE: value }, () => {
      const config = otlpExporterConfigFromEnv("sk-test");
      assert.equal(config.httpAgentOptions?.rejectUnauthorized, false, value);
      assert.equal(config.url, "https://otel.gentrail.ai/v1/traces");
    });
  }
  for (const value of ["false", "0", "no", ""]) {
    await withEnv({ ...TLS_UNSET, OTEL_EXPORTER_OTLP_INSECURE: value }, () => {
      assert.equal(otlpExporterConfigFromEnv("sk-test").httpAgentOptions, undefined, value);
    });
  }
});

test("the CA and the insecure flag combine", async () => {
  await withEnv(
    {
      ...TLS_UNSET,
      OTEL_EXPORTER_OTLP_CERTIFICATE: writeCertificate(),
      OTEL_EXPORTER_OTLP_INSECURE: "true",
    },
    () => {
      const options = otlpExporterConfigFromEnv("sk-test").httpAgentOptions;
      assert.equal(options?.ca?.toString(), PEM);
      assert.equal(options?.rejectUnauthorized, false);
    },
  );
});

test("an unreadable certificate fails the exporter config", async () => {
  await withEnv({ ...TLS_UNSET, OTEL_EXPORTER_OTLP_CERTIFICATE: "/nonexistent/ca.pem" }, () => {
    assert.throws(() => otlpExporterConfigFromEnv("sk-test"), /OTEL_EXPORTER_OTLP_CERTIFICATE/);
  });
});

test("an unreadable certificate leaves tracing off without throwing from init or instrument", async (t) => {
  const warn = t.mock.method(console, "warn", () => undefined);
  await withEnv(
    {
      ...TLS_UNSET,
      GENTRAIL_API_KEY: "sk-test",
      GENTRAIL_DECIDE_ENDPOINT: undefined,
      OTEL_EXPORTER_OTLP_CERTIFICATE: "/nonexistent/ca.pem",
    },
    async () => {
      const gentrail = init();
      assert.equal(gentrail.tracer, null);
      await gentrail.shutdown();
      assert.equal(instrument(), null);
    },
  );
  assert.equal(warn.mock.callCount(), 2);
});
