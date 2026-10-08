import { createHash } from "node:crypto";

import { canonicalJson } from "./canonicalJson.js";

export type DecisionOutcome = "verified" | "request_conflict" | "unavailable";
export interface DecisionReference {
  request_id: string;
  invocation_id: string;
  proposal_hash: string;
  arguments_hash: string;
}

export function isDecisionReference(value: unknown): value is DecisionReference {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;
  for (const identity of [candidate.request_id, candidate.invocation_id]) {
    if (
      typeof identity !== "string" ||
      identity.trim() === "" ||
      Buffer.byteLength(identity) > 256
    ) {
      return false;
    }
  }
  for (const digest of [candidate.proposal_hash, candidate.arguments_hash]) {
    if (typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) {
      return false;
    }
  }
  return true;
}

export function argumentsHash(raw: string): string {
  if (Buffer.byteLength(raw) > 2 * 1024 * 1024) {
    throw new RangeError("observation arguments exceed size limit");
  }
  const decoded: unknown = JSON.parse(raw || "{}");
  const argumentsObject = decoded ?? {};
  if (typeof argumentsObject !== "object" || Array.isArray(argumentsObject)) {
    throw new TypeError("observation arguments must be a JSON object");
  }
  return createHash("sha256").update(canonicalJson(argumentsObject), "utf8").digest("hex");
}

export function checkedReference(
  value: unknown,
  request: Record<string, unknown>,
): DecisionReference | undefined {
  if (!isDecisionReference(value)) {
    return undefined;
  }
  if (value.request_id !== request.request_id || value.invocation_id !== request.invocation_id) {
    return undefined;
  }
  try {
    if (value.arguments_hash !== argumentsHash(JSON.stringify(request.tool_args))) {
      return undefined;
    }
    return { ...value };
  } catch {
    return undefined;
  }
}

export function observationAttributes(
  reference: DecisionReference | undefined,
  argumentsJson: string,
): Record<string, string> {
  if (reference === undefined) {
    return {};
  }
  if (!isDecisionReference(reference)) {
    throw new TypeError("invalid decision reference");
  }
  return {
    "aigentrail.decision.request_id": reference.request_id,
    "aigentrail.decision.invocation_id": reference.invocation_id,
    "aigentrail.decision.proposal_hash": reference.proposal_hash,
    "aigentrail.decision.arguments_hash": argumentsHash(argumentsJson),
  };
}
