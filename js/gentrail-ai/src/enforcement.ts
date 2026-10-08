import { randomUUID } from "node:crypto";

import {
  checkedReference,
  type DecisionOutcome,
  type DecisionReference,
} from "./observationReference.js";

import { trace } from "@opentelemetry/api";

export interface Approval {
  status_url?: string;
}

export interface Verdict {
  outcome?: DecisionOutcome;
  observation_reference?: DecisionReference;
  observations_url?: string;
  decision?: string;
  rule?: string;
  message?: string;
  approval?: Approval;
}

export interface PolicyEnforcerOptions {
  endpoint: string;
  apiKey: string;
  decideTimeoutMs?: number;
  gateTimeoutMs?: number;
  gatePollIntervalMs?: number;
}

export interface DecideOptions {
  agentId?: string;
  invocationId?: string;
  requestId?: string;
}

export interface EnforcementOutcome {
  verdict: Verdict;
  allowed: boolean;
  message: string;
  decision: string;
  rule: string;
}

const USER_AGENT = "gentrail-sdk-js";
const DECIDE_TIMEOUT_MS_DEFAULT = 3000;
const GATE_TIMEOUT_SECONDS_DEFAULT = 120;
const GATE_POLL_INTERVAL_MS_DEFAULT = 2000;
const INVALID_TRACE_ID = "00000000000000000000000000000000";

export class PolicyEnforcer {
  readonly endpoint: string;
  readonly apiKey: string;
  readonly decideTimeoutMs: number;
  readonly gateTimeoutMs: number;
  readonly gatePollIntervalMs: number;

  constructor(options: PolicyEnforcerOptions) {
    const endpoint = options.endpoint.trim().replace(/\/+$/, "");
    const apiKey = options.apiKey.trim();
    if (endpoint === "") {
      throw new Error("PolicyEnforcer needs a decide endpoint");
    }
    if (apiKey === "") {
      throw new Error("PolicyEnforcer needs an API key");
    }
    this.endpoint = endpoint;
    this.apiKey = apiKey;
    this.decideTimeoutMs = positiveOrDefault(options.decideTimeoutMs, DECIDE_TIMEOUT_MS_DEFAULT);
    this.gateTimeoutMs = options.gateTimeoutMs ?? gateTimeoutMsFromEnv();
    this.gatePollIntervalMs = positiveOrDefault(
      options.gatePollIntervalMs,
      GATE_POLL_INTERVAL_MS_DEFAULT,
    );
  }

  static fromEnv(): PolicyEnforcer | null {
    const endpoint = (process.env.GENTRAIL_DECIDE_ENDPOINT ?? "").trim();
    const apiKey = (process.env.GENTRAIL_API_KEY ?? "").trim();
    if (endpoint === "" || apiKey === "") {
      return null;
    }
    return new PolicyEnforcer({ endpoint, apiKey });
  }

  async decide(toolName: string, toolArgs: unknown, options: DecideOptions = {}): Promise<Verdict> {
    const payload: Record<string, unknown> = {
      event_type: "tool_call",
      tool_name: toolName,
      tool_args: toolArgs ?? {},
      request_id: options.requestId || randomUUID(),
    };
    if (options.agentId) {
      payload.agent_id = options.agentId;
    }
    const invocationId = options.invocationId || ambientOtelTraceId();
    if (invocationId) {
      payload.invocation_id = invocationId;
    }
    try {
      return await this.postDecide(payload);
    } catch (err) {
      console.warn(`gentrail decide failed (${String(err)}); allowing tool ${toolName}`);
      return { decision: "ALLOW", outcome: "unavailable" };
    }
  }

  async awaitGate(approval: Approval | undefined): Promise<string> {
    const statusUrl = approval?.status_url;
    if (!statusUrl) {
      return "timeout";
    }
    const pollUrl = this.endpoint + statusUrl;
    const deadline = performance.now() + this.gateTimeoutMs;
    for (;;) {
      let status: string;
      try {
        status = await this.pollGateOnce(pollUrl);
      } catch (err) {
        console.warn(`gentrail gate poll failed (${String(err)}); holding the gate closed`);
        return "timeout";
      }
      if (status !== "pending") {
        return status;
      }
      if (performance.now() >= deadline) {
        return "timeout";
      }
      await sleep(this.gatePollIntervalMs);
    }
  }

  async enforce(
    toolName: string,
    toolArgs: unknown,
    options: DecideOptions = {},
  ): Promise<EnforcementOutcome> {
    const verdict = await this.decide(toolName, toolArgs, options);
    const decision = verdict.decision ?? "";
    const rule = verdict.rule ?? "";
    if (decision === "BLOCK") {
      return { verdict, allowed: false, message: verdictMessage(verdict), decision, rule };
    }
    if (decision === "GATE") {
      const status = await this.awaitGate(verdict.approval);
      if (status === "approved") {
        return { verdict, allowed: true, message: "", decision, rule };
      }
      return {
        verdict,
        allowed: false,
        message: `${verdictMessage(verdict)} (approval ${status})`,
        decision,
        rule,
      };
    }
    return { verdict, allowed: true, message: "", decision, rule };
  }

  private async postDecide(payload: Record<string, unknown>): Promise<Verdict> {
    const response = await fetch(`${this.endpoint}/api/v1/decide`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${this.apiKey}`,
        "User-Agent": USER_AGENT,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(this.decideTimeoutMs),
    });
    if (!response.ok) {
      throw new Error(`decide returned ${response.status}`);
    }
    return parseVerdict(await response.json(), payload);
  }

  private async pollGateOnce(pollUrl: string): Promise<string> {
    const response = await fetch(pollUrl, {
      headers: { Authorization: `Bearer ${this.apiKey}`, "User-Agent": USER_AGENT },
      signal: AbortSignal.timeout(this.decideTimeoutMs),
    });
    if (!response.ok) {
      throw new Error(`gate status returned ${response.status}`);
    }
    const body: unknown = await response.json();
    if (!isRecord(body)) {
      throw new Error("gate status is not a JSON object");
    }
    if (body.status === undefined) {
      return "pending";
    }
    if (typeof body.status !== "string") {
      throw new Error("gate status is not a string");
    }
    return body.status;
  }
}

function parseVerdict(body: unknown, request: Record<string, unknown>): Verdict {
  if (!isRecord(body)) {
    throw new Error("decide verdict is not a JSON object");
  }
  let outcome: DecisionOutcome =
    body.outcome === "verified" || body.outcome === "request_conflict"
      ? body.outcome
      : "unavailable";
  if (body.decision !== "ALLOW" && body.decision !== "BLOCK" && body.decision !== "GATE") {
    outcome = "unavailable";
  }
  const verdict: Verdict = { outcome };
  if (outcome === "verified") {
    const reference = checkedReference(body.observation_reference, request);
    if (reference !== undefined) {
      verdict.observation_reference = reference;
    }
  }
  if (typeof body.observations_url === "string") {
    verdict.observations_url = body.observations_url;
  }
  if (typeof body.decision === "string") {
    verdict.decision = body.decision;
  }
  if (typeof body.rule === "string") {
    verdict.rule = body.rule;
  }
  if (typeof body.message === "string") {
    verdict.message = body.message;
  }
  if (isRecord(body.approval)) {
    verdict.approval =
      typeof body.approval.status_url === "string" ? { status_url: body.approval.status_url } : {};
  }
  return verdict;
}

export function verdictMessage(verdict: Verdict): string {
  return verdict.message || `${verdict.decision ?? ""} by policy ${verdict.rule ?? ""}`.trim();
}

export function ambientOtelTraceId(): string {
  const traceId = trace.getActiveSpan()?.spanContext().traceId;
  if (!traceId || traceId === INVALID_TRACE_ID) {
    return "";
  }
  return traceId;
}

function gateTimeoutMsFromEnv(): number {
  const seconds = Number(
    process.env.GENTRAIL_GATE_TIMEOUT_SECONDS ?? String(GATE_TIMEOUT_SECONDS_DEFAULT),
  );
  if (!Number.isFinite(seconds) || seconds < 0) {
    return GATE_TIMEOUT_SECONDS_DEFAULT * 1000;
  }
  return seconds * 1000;
}

function positiveOrDefault(value: number | undefined, fallback: number): number {
  if (value === undefined) {
    return fallback;
  }
  if (!Number.isFinite(value) || value <= 0) {
    throw new RangeError(`expected a positive duration, got ${value}`);
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function sleep(durationMs: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, durationMs));
}
