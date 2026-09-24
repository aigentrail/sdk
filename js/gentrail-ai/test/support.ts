import { readFileSync } from "node:fs";
import { createServer, type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";

export function readSpecJson(name: string): unknown {
  const packageRoot = new URL("../../", import.meta.url);
  const location = new URL(`../../spec/${name}`, packageRoot);
  return JSON.parse(readFileSync(location, "utf8")) as unknown;
}

export interface StubRoute {
  status?: number;
  json?: unknown;
}

export interface SeenRequest {
  url: string;
  method: string;
  auth: string | undefined;
  userAgent: string | undefined;
  json: unknown;
}

export interface StubServer {
  base: string;
  requests: SeenRequest[];
  close(): Promise<void>;
}

export async function serve(
  handler: (req: IncomingMessage, calls: number) => StubRoute,
): Promise<StubServer> {
  const requests: SeenRequest[] = [];
  let calls = 0;
  const server = createServer((req, res) => {
    let data = "";
    req.on("data", (chunk) => (data += chunk));
    req.on("end", () => {
      calls += 1;
      requests.push({
        url: req.url ?? "",
        method: req.method ?? "",
        auth: req.headers.authorization,
        userAgent: req.headers["user-agent"],
        json:
          data && req.headers["content-type"] === "application/json" ? JSON.parse(data) : undefined,
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

export async function withEnv<T>(
  vars: Record<string, string | undefined>,
  body: () => T | Promise<T>,
): Promise<T> {
  const saved = new Map<string, string | undefined>();
  for (const [name, value] of Object.entries(vars)) {
    saved.set(name, process.env[name]);
    if (value === undefined) {
      delete process.env[name];
    } else {
      process.env[name] = value;
    }
  }
  try {
    return await body();
  } finally {
    for (const [name, value] of saved) {
      if (value === undefined) {
        delete process.env[name];
      } else {
        process.env[name] = value;
      }
    }
  }
}

export function seededRandom(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let mixed = state;
    mixed = Math.imul(mixed ^ (mixed >>> 15), mixed | 1);
    mixed ^= mixed + Math.imul(mixed ^ (mixed >>> 7), mixed | 61);
    return ((mixed ^ (mixed >>> 14)) >>> 0) / 4294967296;
  };
}
