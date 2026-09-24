import assert from "node:assert/strict";
import test from "node:test";

import { context, ROOT_CONTEXT, trace, TraceFlags } from "@opentelemetry/api";
import { AsyncLocalStorageContextManager } from "@opentelemetry/context-async-hooks";

import { PolicyEnforcer, type Verdict } from "../src/index.js";
import { readSpecJson, serve, withEnv } from "./support.js";

interface EnforceVector {
  name: string;
  verdict: Verdict;
  gate_status: string | null;
  allowed: boolean;
  message: string;
}

const fastGate = { gateTimeoutMs: 500, gatePollIntervalMs: 10 };

test("enforce matches the shared enforcement vectors", async () => {
  const vectors = readSpecJson("enforce_vectors.json") as EnforceVector[];
  assert.ok(vectors.length > 0, "no enforcement vectors");
  for (const vector of vectors) {
    const srv = await serve((req) =>
      req.url === "/api/v1/decide"
        ? { json: vector.verdict }
        : { json: { status: vector.gate_status } },
    );
    try {
      const enforcer = new PolicyEnforcer({ endpoint: srv.base, apiKey: "sk-test", ...fastGate });
      const outcome = await enforcer.enforce(
        "wire_money",
        { amount: 5 },
        { agentId: "a", requestId: "r" },
      );
      assert.equal(outcome.allowed, vector.allowed, vector.name);
      assert.equal(outcome.message, vector.message, vector.name);
      const polled = srv.requests.filter((request) => request.url !== "/api/v1/decide");
      assert.equal(
        polled.length > 0,
        vector.gate_status !== null,
        `${vector.name} polled the gate`,
      );
    } finally {
      await srv.close();
    }
  }
});

test("decide sends the client identity and synthesizes a request id", async () => {
  const srv = await serve(() => ({ json: { decision: "ALLOW" } }));
  try {
    const enforcer = new PolicyEnforcer({ endpoint: srv.base + "/", apiKey: "sk-test" });
    const verdict = await enforcer.decide("lookup", { id: 1 });
    assert.deepEqual(verdict, { decision: "ALLOW" });
    const [request] = srv.requests;
    assert.equal(request.url, "/api/v1/decide");
    assert.equal(request.userAgent, "gentrail-sdk-js");
    const body = request.json as Record<string, unknown>;
    assert.match(String(body.request_id), /^[0-9a-f-]{36}$/);
    assert.equal(body.agent_id, undefined);
    assert.equal(body.invocation_id, undefined);
  } finally {
    await srv.close();
  }
});

test("decide falls back to the ambient OpenTelemetry trace id", async () => {
  const contextManager = new AsyncLocalStorageContextManager().enable();
  context.setGlobalContextManager(contextManager);
  const srv = await serve(() => ({ json: { decision: "ALLOW" } }));
  try {
    const enforcer = new PolicyEnforcer({ endpoint: srv.base, apiKey: "sk-test" });
    const traceId = "0af7651916cd43dd8448eb211c80319c";
    const span = trace.wrapSpanContext({
      traceId,
      spanId: "b7ad6b7169203331",
      traceFlags: TraceFlags.SAMPLED,
    });
    await context.with(trace.setSpan(ROOT_CONTEXT, span), () =>
      enforcer.decide("lookup", {}, { requestId: "r1" }),
    );
    await enforcer.decide("lookup", {}, { requestId: "r2", invocationId: "explicit" });
    assert.equal((srv.requests[0].json as Record<string, unknown>).invocation_id, traceId);
    assert.equal((srv.requests[1].json as Record<string, unknown>).invocation_id, "explicit");
  } finally {
    context.disable();
    await srv.close();
  }
});

test("decide fails open on a malformed verdict", async () => {
  const srv = await serve(() => ({ json: ["BLOCK"] }));
  try {
    const enforcer = new PolicyEnforcer({ endpoint: srv.base, apiKey: "sk-test" });
    const outcome = await enforcer.enforce("lookup", {});
    assert.deepEqual(outcome, { allowed: true, message: "", decision: "ALLOW", rule: "" });
  } finally {
    await srv.close();
  }
});

test("awaitGate fails closed without a status url or on a malformed status", async () => {
  const srv = await serve(() => ({ json: { status: 7 } }));
  try {
    const enforcer = new PolicyEnforcer({ endpoint: srv.base, apiKey: "sk-test", ...fastGate });
    assert.equal(await enforcer.awaitGate(undefined), "timeout");
    assert.equal(await enforcer.awaitGate({}), "timeout");
    assert.equal(await enforcer.awaitGate({ status_url: "/api/v1/approvals/x" }), "timeout");
  } finally {
    await srv.close();
  }
});

test("fromEnv needs both the decide endpoint and the API key", async () => {
  await withEnv({ GENTRAIL_DECIDE_ENDPOINT: undefined, GENTRAIL_API_KEY: "sk" }, () => {
    assert.equal(PolicyEnforcer.fromEnv(), null);
  });
  await withEnv({ GENTRAIL_DECIDE_ENDPOINT: "https://x.example", GENTRAIL_API_KEY: " " }, () => {
    assert.equal(PolicyEnforcer.fromEnv(), null);
  });
  await withEnv(
    {
      GENTRAIL_DECIDE_ENDPOINT: "https://x.example/",
      GENTRAIL_API_KEY: "sk",
      GENTRAIL_GATE_TIMEOUT_SECONDS: "7",
    },
    () => {
      const enforcer = PolicyEnforcer.fromEnv();
      assert.equal(enforcer?.endpoint, "https://x.example");
      assert.equal(enforcer?.decideTimeoutMs, 3000);
      assert.equal(enforcer?.gateTimeoutMs, 7000);
      assert.equal(enforcer?.gatePollIntervalMs, 2000);
    },
  );
});
