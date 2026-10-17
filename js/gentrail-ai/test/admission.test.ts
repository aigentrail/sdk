import assert from "node:assert/strict";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import test from "node:test";
import { PolicyEnforcer, guardTools } from "../src/index.js";
import { AdmissionClient, boundedJson } from "../src/admission.js";
import { readSpecJson, withEnv } from "./support.js";

interface Vector {
  name: string;
  link: Record<string, unknown>;
  reserved: Record<string, unknown>;
  consumed: Record<string, unknown>;
  allowed: boolean;
}
const vectors = readSpecJson("admission_vectors.json") as Vector[];

async function quotaServer(
  options: {
    vector?: Vector;
    gate?: string;
    lost?: boolean;
    redirect?: boolean;
    verdict?: unknown;
    liveTime?: boolean;
    slow?: boolean;
  } = {},
) {
  const vector = structuredClone(options.vector ?? vectors[0]);
  if (options.liveTime) {
    const now = Math.floor(Date.now() / 1000);
    for (const receipt of [vector.reserved, vector.consumed]) {
      Object.assign(receipt.reservation as object, {
        window_start: now - 10,
        expires_at: now + 60,
        window_end: now + 120,
      });
    }
  }
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  let consumes = 0;
  const server = createServer((req, res) => {
    let raw = "";
    req.on("data", (chunk) => {
      raw += chunk;
    });
    req.on("end", () => {
      const path = req.url ?? "";
      const body = raw ? (JSON.parse(raw) as Record<string, unknown>) : {};
      calls.push({ path, body });
      assert.equal(req.headers.authorization, "Bearer key");
      let reply: unknown;
      if (path === "/api/v1/decide") {
        reply = Object.hasOwn(options, "verdict")
          ? options.verdict
          : {
              decision: options.gate ? "GATE" : "ALLOW",
              outcome: "verified",
              admission: vector.link,
              ...(options.gate
                ? { approval: { status_url: "/approval" } }
                : {}),
            };
      } else if (path === "/approval") {
        reply = { status: options.gate };
      } else {
        assert.equal(req.method, "POST");
        assert.deepEqual(body, { proposal_hash: vector.link.proposal_hash });
        if (options.redirect) {
          res.writeHead(307, { location: "/unexpected" }).end();
          return;
        }
        if (path === "/reserve") {
          reply = vector.reserved;
        } else {
          assert.equal(path, "/consume");
          consumes++;
          if (options.lost) {
            req.socket.destroy();
            return;
          }
          reply = {
            ...vector.consumed,
            execution_authorized:
              consumes === 1 ? vector.consumed.execution_authorized : false,
          };
        }
      }
      res.writeHead(200, { "content-type": "application/json" });
      if (options.slow && path !== "/api/v1/decide") {
        res.flushHeaders();
        const timer = setTimeout(() => res.end(JSON.stringify(reply)), 300);
        res.on("close", () => clearTimeout(timer));
      } else {
        res.end(JSON.stringify(reply));
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  return {
    endpoint: `http://127.0.0.1:${port}`,
    calls,
    get consumes() {
      return consumes;
    },
    async close() {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

function client(endpoint: string): PolicyEnforcer {
  return new PolicyEnforcer({
    endpoint,
    apiKey: "key",
    strictAdmission: true,
    now: () => 100000,
    idGen: () => "call",
  });
}

test("strict admission matches every shared Go/Python receipt vector", async () => {
  assert.ok(vectors.length > 0);
  for (const vector of vectors) {
    const srv = await quotaServer({ vector });
    try {
      const result = await client(srv.endpoint).enforce("Read", {});
      assert.equal(result.allowed, vector.allowed, vector.name);
      if (vector.name === "quota exhausted") {
        assert.equal(
          result.message,
          "This agent has used its tool-call allowance for the current quota window.",
        );
      }
      assert.equal(srv.calls[0].body.admission_protocol, "quota_v1");
      assert.ok(srv.consumes <= 1);
    } finally {
      await srv.close();
    }
  }
});

test("approval precedes reservation; denied and expired holds never consume", async () => {
  for (const gate of ["approved", "denied", "expired"]) {
    const srv = await quotaServer({ gate });
    try {
      assert.equal(
        (await client(srv.endpoint).enforce("Read", {})).allowed,
        gate === "approved",
      );
      assert.deepEqual(
        srv.calls.map((call) => call.path),
        gate === "approved"
          ? ["/api/v1/decide", "/approval", "/reserve", "/consume"]
          : ["/api/v1/decide", "/approval"],
      );
    } finally {
      await srv.close();
    }
  }
});

test("decide alone never consumes; replay cannot authorize execution twice", async () => {
  const srv = await quotaServer();
  try {
    const enforcer = client(srv.endpoint);
    assert.equal((await enforcer.decide("Read", {})).decision, "ALLOW");
    assert.equal(srv.consumes, 0);
    assert.equal((await enforcer.enforce("Read", {})).allowed, true);
    assert.equal((await enforcer.enforce("Read", {})).allowed, false);
    assert.equal(srv.consumes, 2);
  } finally {
    await srv.close();
  }
});

test("lost consume replies and redirects never retry or authorize", async () => {
  for (const options of [{ lost: true }, { redirect: true }]) {
    const srv = await quotaServer(options);
    try {
      assert.equal(
        (await client(srv.endpoint).enforce("Read", {})).allowed,
        false,
      );
      assert.equal(srv.consumes, options.lost ? 1 : 0);
      assert.ok(srv.calls.every((call) => call.path !== "/unexpected"));
    } finally {
      await srv.close();
    }
  }
});

test("strict decisions fail closed on outages and malformed authority", async () => {
  assert.equal(
    (await client("http://127.0.0.1:1").enforce("Read", {})).allowed,
    false,
  );
  for (const verdict of [
    null,
    {},
    { decision: "ALLOW" },
    { decision: "ALLOW", outcome: "unknown" },
    { decision: "ALLOW", outcome: "request_conflict" },
    { decision: "SHADOW", outcome: "verified" },
    ...[null, false, {}].map((admission) => ({
      decision: "ALLOW",
      outcome: "verified",
      admission,
    })),
  ]) {
    const srv = await quotaServer({ verdict });
    try {
      assert.equal(
        (await client(srv.endpoint).enforce("Read", {})).allowed,
        false,
      );
      assert.equal(srv.calls.length, 1);
    } finally {
      await srv.close();
    }
  }
});

test("verified non-quota decisions do not add admission requests", async () => {
  const srv = await quotaServer({
    verdict: { decision: "ALLOW", outcome: "verified" },
  });
  try {
    assert.equal(
      (await client(srv.endpoint).enforce("Read", {})).allowed,
      true,
    );
    assert.equal(srv.calls.length, 1);
  } finally {
    await srv.close();
  }
});

test("guardTools consumes at execution and refuses replay", async () => {
  const srv = await quotaServer({ liveTime: true });
  let executed = 0;
  try {
    const tools = guardTools(
      {
        Read: {
          async execute(_input: object, _options: { toolCallId: string }) {
            executed++;
            return "ran";
          },
        },
      },
      {
        endpoint: srv.endpoint,
        apiKey: "key",
        strictAdmission: true,
      },
    );
    assert.equal(await tools.Read.execute({}, { toolCallId: "call" }), "ran");
    await assert.rejects(tools.Read.execute({}, { toolCallId: "call" }));
    assert.equal(executed, 1);
    assert.equal(srv.consumes, 2);
  } finally {
    await srv.close();
  }
});

test("guardTools strict opt-in cannot silently disable missing configuration", async () => {
  await withEnv(
    { GENTRAIL_DECIDE_ENDPOINT: undefined, GENTRAIL_API_KEY: undefined },
    () => {
      assert.throws(() => guardTools({}, { strictAdmission: true }));
      assert.throws(() => PolicyEnforcer.fromEnv({ strictAdmission: true }));
    },
  );
});

test("admission receipt sizes and stalled responses are bounded", async () => {
  const vector = structuredClone(vectors[0]);
  vector.reserved.padding = "x".repeat(65536);
  const oversized = await quotaServer({ vector });
  try {
    assert.equal(
      (await client(oversized.endpoint).enforce("Read", {})).allowed,
      false,
    );
    assert.equal(oversized.consumes, 0);
  } finally {
    await oversized.close();
  }
  const slow = await quotaServer({ slow: true });
  try {
    const admission = new AdmissionClient(
      slow.endpoint + "/api/v1/decide",
      "key",
      50,
      () => 100000,
    );
    const start = performance.now();
    await assert.rejects(admission.authorize("call", vectors[0].link));
    assert.ok(performance.now() - start < 250);
    assert.equal(slow.consumes, 0);
  } finally {
    await slow.close();
  }
  await assert.rejects(boundedJson(new Response("x".repeat(65)), 64));
});
