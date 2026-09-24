const CANONICAL_JSON_DEPTH_MAX = 256;

export function canonicalJson(value: unknown): string {
  return canonicalJsonAtDepth(value, 0);
}

function canonicalJsonAtDepth(value: unknown, depth: number): string {
  if (depth > CANONICAL_JSON_DEPTH_MAX) {
    throw new RangeError(`canonical JSON nests deeper than ${CANONICAL_JSON_DEPTH_MAX} levels`);
  }
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("canonical JSON has no NaN or Infinity");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return canonicalArray(value, depth);
  }
  if (isPlainObject(value)) {
    return canonicalObject(value, depth);
  }
  throw new TypeError(`${describeType(value)} is not canonical JSON`);
}

function canonicalArray(items: readonly unknown[], depth: number): string {
  const parts: string[] = [];
  for (let index = 0; index < items.length; index += 1) {
    if (!(index in items)) {
      throw new TypeError("canonical JSON arrays cannot have holes");
    }
    parts.push(canonicalJsonAtDepth(items[index], depth + 1));
  }
  return "[" + parts.join(",") + "]";
}

function canonicalObject(object: Record<string, unknown>, depth: number): string {
  const keys = Object.keys(object).sort();
  const members = keys.map(
    (key) => JSON.stringify(key) + ":" + canonicalJsonAtDepth(object[key], depth + 1),
  );
  return "{" + members.join(",") + "}";
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const prototype: unknown = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function describeType(value: unknown): string {
  if (typeof value === "object" && value !== null) {
    return value.constructor?.name ?? "object";
  }
  return typeof value;
}
