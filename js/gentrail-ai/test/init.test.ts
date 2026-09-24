import assert from "node:assert/strict";
import test from "node:test";

import { EvidenceLedger, GovernanceTracer, init, PolicyEnforcer } from "../src/index.js";
import { withEnv } from "./support.js";

test("init degrades to a local ledger when nothing is configured", async () => {
  await withEnv(
    {
      GENTRAIL_API_KEY: undefined,
      GENTRAIL_DECIDE_ENDPOINT: undefined,
      AIGENTRAIL_API_KEY: undefined,
      OTEL_EXPORTER_OTLP_ENDPOINT: undefined,
    },
    async () => {
      const gentrail = init();
      assert.equal(gentrail.tracer, null);
      assert.equal(gentrail.enforcer, null);
      assert.ok(gentrail.ledger instanceof EvidenceLedger);
      await gentrail.flush();
      await gentrail.shutdown();
    },
  );
});

test("init builds the tracer and enforcer from the environment", async () => {
  await withEnv(
    {
      GENTRAIL_API_KEY: "sk-test",
      GENTRAIL_DECIDE_ENDPOINT: "https://decide.example",
      OTEL_EXPORTER_OTLP_ENDPOINT: "http://127.0.0.1:9",
    },
    async () => {
      const gentrail = init();
      assert.ok(gentrail.tracer instanceof GovernanceTracer);
      assert.ok(gentrail.enforcer instanceof PolicyEnforcer);
      assert.equal(gentrail.enforcer.endpoint, "https://decide.example");
      await gentrail.flush();
      await gentrail.shutdown();
    },
  );
});
