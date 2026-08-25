/*
Gentrail inline policy enforcement for Vercel AI SDK tools.

guardTools wraps each tool's execute so the Gentrail decide endpoint rules on
the call before it runs. BLOCK and an unapproved GATE throw GentrailPolicyError:
the AI SDK documents that errors thrown inside execute become tool-error content
parts forwarded to the model, so the model sees the policy message and the run
continues. decide fails open on transport errors (a backend outage must never
break the agent); an unresolved GATE fails closed (running a gated action
without a confirmed approval is what the gate exists to prevent).
*/

export interface GuardOptions {
  endpoint?: string;
  apiKey?: string;
  agentId?: string;
  invocationId?: string;
  decideTimeoutMs?: number;
  gateTimeoutMs?: number;
  gatePollIntervalMs?: number;
}

export class GentrailPolicyError extends Error {
  readonly decision: string;
  readonly rule: string;

  constructor(message: string, decision: string, rule: string) {
    super(message);
    this.name = "GentrailPolicyError";
    this.decision = decision;
    this.rule = rule;
  }
}

interface ToolExecuteOptions {
  toolCallId?: string;
}

type ToolExecute = (...args: never[]) => unknown;

interface GuardableTool {
  execute?: ToolExecute;
}

interface Verdict {
  decision?: string;
  rule?: string;
  message?: string;
  approval?: { status_url?: string };
}

interface Config {
  endpoint: string;
  apiKey: string;
  agentId: string;
  invocationId: string;
  decideTimeoutMs: number;
  gateTimeoutMs: number;
  gatePollIntervalMs: number;
}

function resolveConfig(options: GuardOptions): Config | null {
  const endpoint = (options.endpoint ?? process.env.GENTRAIL_DECIDE_ENDPOINT ?? "")
    .trim()
    .replace(/\/+$/, "");
  const apiKey = (options.apiKey ?? process.env.GENTRAIL_API_KEY ?? "").trim();
  if (!endpoint || !apiKey) {
    return null;
  }
  const gateSeconds = Number(process.env.GENTRAIL_GATE_TIMEOUT_SECONDS ?? "120");
  return {
    endpoint,
    apiKey,
    agentId: options.agentId ?? "",
    invocationId: options.invocationId ?? "",
    decideTimeoutMs: options.decideTimeoutMs ?? 3000,
    gateTimeoutMs:
      options.gateTimeoutMs ?? (Number.isFinite(gateSeconds) ? gateSeconds * 1000 : 120000),
    gatePollIntervalMs: options.gatePollIntervalMs ?? 2000,
  };
}

async function decide(
  cfg: Config,
  toolName: string,
  toolArgs: unknown,
  requestId: string,
): Promise<Verdict> {
  const payload: Record<string, unknown> = {
    event_type: "tool_call",
    tool_name: toolName,
    tool_args: toolArgs ?? {},
  };
  if (cfg.agentId) payload.agent_id = cfg.agentId;
  if (cfg.invocationId) payload.invocation_id = cfg.invocationId;
  if (requestId) payload.request_id = requestId;
  try {
    const res = await fetch(`${cfg.endpoint}/api/v1/decide`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${cfg.apiKey}`,
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(cfg.decideTimeoutMs),
    });
    if (!res.ok) {
      throw new Error(`decide returned ${res.status}`);
    }
    return (await res.json()) as Verdict;
  } catch (err) {
    console.warn(`gentrail decide failed (${err}); allowing tool ${toolName}`);
    return { decision: "ALLOW" };
  }
}

async function awaitGate(cfg: Config, statusUrl: string): Promise<string> {
  const pollUrl = cfg.endpoint + statusUrl;
  const deadline = Date.now() + cfg.gateTimeoutMs;
  for (;;) {
    let status: string;
    try {
      const res = await fetch(pollUrl, {
        headers: { Authorization: `Bearer ${cfg.apiKey}` },
        signal: AbortSignal.timeout(cfg.decideTimeoutMs),
      });
      if (!res.ok) {
        throw new Error(`gate status returned ${res.status}`);
      }
      status = ((await res.json()) as { status?: string }).status ?? "pending";
    } catch (err) {
      console.warn(`gentrail gate poll failed (${err}); holding the gate closed`);
      return "timeout";
    }
    if (status !== "pending") {
      return status;
    }
    if (Date.now() >= deadline) {
      return "timeout";
    }
    await new Promise((resolve) => setTimeout(resolve, cfg.gatePollIntervalMs));
  }
}

function verdictMessage(verdict: Verdict): string {
  return verdict.message || `${verdict.decision ?? ""} by policy ${verdict.rule ?? ""}`.trim();
}

async function enforce(
  cfg: Config,
  toolName: string,
  input: unknown,
  requestId: string,
): Promise<void> {
  const verdict = await decide(cfg, toolName, input, requestId);
  if (verdict.decision === "BLOCK") {
    throw new GentrailPolicyError(verdictMessage(verdict), "BLOCK", verdict.rule ?? "");
  }
  if (verdict.decision === "GATE") {
    const statusUrl = verdict.approval?.status_url;
    const status = statusUrl ? await awaitGate(cfg, statusUrl) : "timeout";
    if (status !== "approved") {
      throw new GentrailPolicyError(
        `${verdictMessage(verdict)} (approval ${status})`,
        "GATE",
        verdict.rule ?? "",
      );
    }
  }
}

export function guardTools<T extends Record<string, object>>(
  tools: T,
  options: GuardOptions = {},
): T {
  const cfg = resolveConfig(options);
  if (!cfg) {
    return tools;
  }
  const guarded: Record<string, object> = {};
  for (const [name, tool] of Object.entries(tools) as [string, GuardableTool][]) {
    const execute = tool.execute;
    if (typeof execute !== "function") {
      guarded[name] = tool;
      continue;
    }
    guarded[name] = {
      ...tool,
      execute: (async (input: unknown, execOptions?: ToolExecuteOptions) => {
        const requestId = execOptions?.toolCallId ?? crypto.randomUUID();
        await enforce(cfg, name, input, requestId);
        return (execute as (input: unknown, options?: ToolExecuteOptions) => unknown)(
          input,
          execOptions,
        );
      }) as ToolExecute,
    };
  }
  return guarded as T;
}
