import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";

import { GentrailPolicyError, guardTools } from "../src/index.js";

interface Route {
  status?: number;
  json?: unknown;
}

interface Seen {
  url: string;
  auth: string | undefined;
  json: unknown;
}

async function serve(handler: (req: IncomingMessage, calls: number) => Route) {
  const requests: Seen[] = [];
  let calls = 0;
  const server = createServer((req, res) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      calls += 1;
      requests.push({
        url: req.url ?? "",
        auth: req.headers.authorization,
        json: data ? JSON.parse(data) : undefined,
      });
      const route = handler(req, calls);
      res.statusCode = route.status ?? 200;
      res.setHeader("content-type", "application/json");
      res.end(JSON.stringify(route.json ?? {}));
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    base: `http://127.0.0.1:${port}`,
    requests,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function sqlTool() {
  const state = { ran: false };
  const tools = {
    run_sql: {
      description: "run sql",
      execute: async (input: { sql: string }, _options?: { toolCallId?: string }) => {
        state.ran = true;
        return `ran ${input.sql}`;
      },
    },
  };
  return { tools, state };
}

const fastGate = { gateTimeoutMs: 500, gatePollIntervalMs: 10 };

test("ALLOW passes through and sends the decide contract", async () => {
  const srv = await serve(() => ({ json: { decision: "ALLOW" } }));
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, {
      endpoint: srv.base,
      apiKey: "sk-test",
      agentId: "reporter",
      invocationId: "inv-1",
    });
    const result = await guarded.run_sql.execute({ sql: "SELECT 1" }, { toolCallId: "call-1" });
    assert.equal(result, "ran SELECT 1");
    assert.equal(state.ran, true);
    assert.equal(srv.requests.length, 1);
    assert.equal(srv.requests[0].url, "/api/v1/decide");
    assert.equal(srv.requests[0].auth, "Bearer sk-test");
    assert.deepEqual(srv.requests[0].json, {
      event_type: "tool_call",
      tool_name: "run_sql",
      tool_args: { sql: "SELECT 1" },
      agent_id: "reporter",
      invocation_id: "inv-1",
      request_id: "call-1",
    });
  } finally {
    await srv.close();
  }
});

test("BLOCK throws GentrailPolicyError and the tool never runs", async () => {
  const srv = await serve(() => ({
    json: { decision: "BLOCK", rule: "no-ddl", message: "DDL is blocked by policy no-ddl" },
  }));
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, { endpoint: srv.base, apiKey: "sk-test" });
    await assert.rejects(
      guarded.run_sql.execute({ sql: "DROP TABLE users" }, { toolCallId: "call-2" }),
      (err: unknown) =>
        err instanceof GentrailPolicyError &&
        err.decision === "BLOCK" &&
        err.rule === "no-ddl" &&
        err.message === "DDL is blocked by policy no-ddl",
    );
    assert.equal(state.ran, false);
  } finally {
    await srv.close();
  }
});

test("GATE runs the tool once the hold is approved", async () => {
  let polls = 0;
  const srv = await serve((req) => {
    if (req.url === "/api/v1/decide") {
      return {
        json: {
          decision: "GATE",
          rule: "wire-transfers",
          approval: { status_url: "/api/v1/approvals/h1" },
        },
      };
    }
    polls += 1;
    return { json: { status: polls < 3 ? "pending" : "approved" } };
  });
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, { endpoint: srv.base, apiKey: "sk-test", ...fastGate });
    const result = await guarded.run_sql.execute({ sql: "SELECT 2" }, { toolCallId: "call-3" });
    assert.equal(result, "ran SELECT 2");
    assert.equal(state.ran, true);
    assert.ok(polls >= 3);
    assert.equal(srv.requests[1].url, "/api/v1/approvals/h1");
    assert.equal(srv.requests[1].auth, "Bearer sk-test");
  } finally {
    await srv.close();
  }
});

test("GATE denied throws and the tool never runs", async () => {
  const srv = await serve((req) =>
    req.url === "/api/v1/decide"
      ? {
          json: {
            decision: "GATE",
            rule: "wire-transfers",
            message: "held for approval",
            approval: { status_url: "/api/v1/approvals/h2" },
          },
        }
      : { json: { status: "denied" } },
  );
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, { endpoint: srv.base, apiKey: "sk-test", ...fastGate });
    await assert.rejects(
      guarded.run_sql.execute({ sql: "SELECT 3" }, { toolCallId: "call-4" }),
      (err: unknown) =>
        err instanceof GentrailPolicyError &&
        err.decision === "GATE" &&
        err.message === "held for approval (approval denied)",
    );
    assert.equal(state.ran, false);
  } finally {
    await srv.close();
  }
});

test("GATE fails closed when the hold never resolves", async () => {
  const srv = await serve((req) =>
    req.url === "/api/v1/decide"
      ? {
          json: {
            decision: "GATE",
            rule: "wire-transfers",
            approval: { status_url: "/api/v1/approvals/h3" },
          },
        }
      : { json: { status: "pending" } },
  );
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, {
      endpoint: srv.base,
      apiKey: "sk-test",
      gateTimeoutMs: 100,
      gatePollIntervalMs: 20,
    });
    await assert.rejects(
      guarded.run_sql.execute({ sql: "SELECT 4" }, { toolCallId: "call-5" }),
      (err: unknown) =>
        err instanceof GentrailPolicyError && err.message.endsWith("(approval timeout)"),
    );
    assert.equal(state.ran, false);
  } finally {
    await srv.close();
  }
});

test("GATE fails closed when the status poll errors", async () => {
  const srv = await serve((req) =>
    req.url === "/api/v1/decide"
      ? {
          json: {
            decision: "GATE",
            rule: "wire-transfers",
            approval: { status_url: "/api/v1/approvals/h4" },
          },
        }
      : { status: 500 },
  );
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, { endpoint: srv.base, apiKey: "sk-test", ...fastGate });
    await assert.rejects(
      guarded.run_sql.execute({ sql: "SELECT 5" }, { toolCallId: "call-6" }),
      (err: unknown) =>
        err instanceof GentrailPolicyError && err.message.endsWith("(approval timeout)"),
    );
    assert.equal(state.ran, false);
  } finally {
    await srv.close();
  }
});

test("decide fails open on transport errors", async () => {
  const { tools, state } = sqlTool();
  const guarded = guardTools(tools, {
    endpoint: "http://127.0.0.1:9",
    apiKey: "sk-test",
    decideTimeoutMs: 200,
  });
  const result = await guarded.run_sql.execute({ sql: "SELECT 6" }, { toolCallId: "call-7" });
  assert.equal(result, "ran SELECT 6");
  assert.equal(state.ran, true);
});

test("decide fails open on a non-2xx response", async () => {
  const srv = await serve(() => ({ status: 500 }));
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools, { endpoint: srv.base, apiKey: "sk-test" });
    const result = await guarded.run_sql.execute({ sql: "SELECT 7" }, { toolCallId: "call-8" });
    assert.equal(result, "ran SELECT 7");
    assert.equal(state.ran, true);
  } finally {
    await srv.close();
  }
});

test("unconfigured guardTools returns the tools untouched", () => {
  const saved = {
    endpoint: process.env.GENTRAIL_DECIDE_ENDPOINT,
    apiKey: process.env.GENTRAIL_API_KEY,
  };
  delete process.env.GENTRAIL_DECIDE_ENDPOINT;
  delete process.env.GENTRAIL_API_KEY;
  try {
    const { tools } = sqlTool();
    assert.equal(guardTools(tools), tools);
  } finally {
    if (saved.endpoint !== undefined) process.env.GENTRAIL_DECIDE_ENDPOINT = saved.endpoint;
    if (saved.apiKey !== undefined) process.env.GENTRAIL_API_KEY = saved.apiKey;
  }
});

test("endpoint and key come from the environment by default", async () => {
  const srv = await serve(() => ({ json: { decision: "BLOCK", rule: "r1" } }));
  const saved = {
    endpoint: process.env.GENTRAIL_DECIDE_ENDPOINT,
    apiKey: process.env.GENTRAIL_API_KEY,
  };
  process.env.GENTRAIL_DECIDE_ENDPOINT = srv.base;
  process.env.GENTRAIL_API_KEY = "sk-env";
  try {
    const { tools, state } = sqlTool();
    const guarded = guardTools(tools);
    await assert.rejects(
      guarded.run_sql.execute({ sql: "SELECT 8" }, { toolCallId: "call-9" }),
      (err: unknown) => err instanceof GentrailPolicyError && err.message === "BLOCK by policy r1",
    );
    assert.equal(state.ran, false);
    assert.equal(srv.requests[0].auth, "Bearer sk-env");
  } finally {
    if (saved.endpoint !== undefined) process.env.GENTRAIL_DECIDE_ENDPOINT = saved.endpoint;
    else delete process.env.GENTRAIL_DECIDE_ENDPOINT;
    if (saved.apiKey !== undefined) process.env.GENTRAIL_API_KEY = saved.apiKey;
    else delete process.env.GENTRAIL_API_KEY;
    await srv.close();
  }
});

test("tools without execute pass through unwrapped", () => {
  const clientTool = { description: "client side only" };
  const guarded = guardTools(
    { render_chart: clientTool },
    { endpoint: "http://127.0.0.1:9", apiKey: "sk-test" },
  );
  assert.equal(guarded.render_chart, clientTool);
});

// The ambient lookup is best-effort: an app without @opentelemetry/api must
// still get a verdict, just an unjoinable one the backend refuses to record.
test("invocation_id is omitted when there is no ambient OTel trace", async () => {
  const srv = await serve(() => ({ json: { decision: "ALLOW" } }));
  try {
    const { tools } = sqlTool();
    const guarded = guardTools(tools, {
      endpoint: srv.base,
      apiKey: "sk-test",
      agentId: "reporter",
    });
    await guarded.run_sql.execute({ sql: "SELECT 1" }, { toolCallId: "call-1" });
    assert.deepEqual(srv.requests[0].json, {
      event_type: "tool_call",
      tool_name: "run_sql",
      tool_args: { sql: "SELECT 1" },
      agent_id: "reporter",
      request_id: "call-1",
    });
  } finally {
    await srv.close();
  }
});
