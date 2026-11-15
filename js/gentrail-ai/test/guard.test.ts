import assert from "node:assert/strict";
import test from "node:test";

import { GentrailPolicyError, guardTools } from "../src/index.js";
import { serve, withEnv } from "./support.js";

test("configured guards require an explicit registered mapping before execution", async () => {
  let executions = 0;
  const tools = {
    Read: {
      async execute() {
        executions++;
      },
    },
  };
  const options = { endpoint: "http://127.0.0.1:9", apiKey: "key" };
  for (const toolIds of [
    undefined,
    {},
    { Read: " " },
    Object.create({ Read: "inherited" }),
  ]) {
    assert.throws(
      () => guardTools(tools, { ...options, toolIds }),
      /registered tool ID/,
    );
  }
  const guarded = guardTools(tools, {
    ...options,
    toolIds: { Read: "registered-read" },
  });
  await assert.rejects(guarded.Read.execute(), GentrailPolicyError);
  assert.equal(executions, 0);
});

test("guards never execute on outages or failed decision responses", async () => {
  for (const response of [
    { status: 500 },
    { json: [] },
    { json: { decision: "ALLOW" } },
    { json: { decision: "ALLOW", outcome: "verified" } },
  ]) {
    const srv = await serve(() => response);
    let executions = 0;
    try {
      const tools = guardTools(
        {
          Read: {
            async execute() {
              executions++;
            },
          },
        },
        {
          endpoint: srv.base,
          apiKey: "key",
          toolIds: { Read: "registered-read" },
        },
      );
      await assert.rejects(tools.Read.execute(), GentrailPolicyError);
      assert.equal(executions, 0);
      assert.equal(srv.requests.length, 1);
      const proposal = srv.requests[0].json as Record<string, unknown>;
      assert.equal(proposal.tool_id, "registered-read");
      assert.equal(proposal.admission_protocol, "operation_v1");
    } finally {
      await srv.close();
    }
  }
});

test("observe-only tools remain untouched without enforcement configuration", async () => {
  const tools = { Read: { execute() {} } };
  await withEnv(
    { GENTRAIL_DECIDE_ENDPOINT: undefined, GENTRAIL_API_KEY: undefined },
    () => {
      assert.equal(guardTools(tools), tools);
      assert.throws(() => guardTools(tools, { apiKey: "key" }));
      assert.throws(() =>
        guardTools(tools, { endpoint: "https://headless.test" }),
      );
    },
  );
});

test("non-executable tools do not require a registered mapping", () => {
  const render = { description: "client-only rendering" };
  const guarded = guardTools(
    { render },
    { endpoint: "https://headless.test", apiKey: "key" },
  );
  assert.equal(guarded.render, render);
});
