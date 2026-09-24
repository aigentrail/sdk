import { readFileSync } from "node:fs";

export function readVendoredJson(name: string): unknown {
  const location = new URL(`../../data/${name}`, import.meta.url);
  return JSON.parse(readFileSync(location, "utf8")) as unknown;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function stringArray(value: unknown, what: string): string[] {
  if (value === undefined || value === null) {
    return [];
  }
  if (!Array.isArray(value) || !value.every((item) => typeof item === "string")) {
    throw new Error(`vendored ${what} must be an array of strings`);
  }
  return value as string[];
}
