import { randomUUID } from "node:crypto";

import { PolicyEnforcer } from "./enforcement.js";

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

type ExecuteWithOptions = (input: unknown, options?: ToolExecuteOptions) => unknown;

interface GuardableTool {
  execute?: ToolExecute;
}

function enforcerFromGuardOptions(options: GuardOptions): PolicyEnforcer | null {
  const endpoint = (options.endpoint ?? process.env.GENTRAIL_DECIDE_ENDPOINT ?? "").trim();
  const apiKey = (options.apiKey ?? process.env.GENTRAIL_API_KEY ?? "").trim();
  if (endpoint === "" || apiKey === "") {
    return null;
  }
  return new PolicyEnforcer({
    endpoint,
    apiKey,
    decideTimeoutMs: options.decideTimeoutMs,
    gateTimeoutMs: options.gateTimeoutMs,
    gatePollIntervalMs: options.gatePollIntervalMs,
  });
}

export function guardTools<T extends Record<string, object>>(
  tools: T,
  options: GuardOptions = {},
): T {
  const enforcer = enforcerFromGuardOptions(options);
  if (enforcer === null) {
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
      execute: guardedExecute(enforcer, name, execute as ExecuteWithOptions, options),
    };
  }
  return guarded as T;
}

function guardedExecute(
  enforcer: PolicyEnforcer,
  toolName: string,
  execute: ExecuteWithOptions,
  options: GuardOptions,
): ToolExecute {
  return (async (input: unknown, executeOptions?: ToolExecuteOptions) => {
    const outcome = await enforcer.enforce(toolName, input, {
      agentId: options.agentId,
      invocationId: options.invocationId,
      requestId: executeOptions?.toolCallId ?? randomUUID(),
    });
    if (!outcome.allowed) {
      throw new GentrailPolicyError(outcome.message, outcome.decision, outcome.rule);
    }
    return execute(input, executeOptions);
  }) as ToolExecute;
}
