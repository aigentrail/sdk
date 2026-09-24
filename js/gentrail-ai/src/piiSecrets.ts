import { Buffer } from "node:buffer";

import RE2 from "re2";

import { isRecord, readVendoredJson, stringArray } from "./piiData.js";
import type { NormalizedText, PIIClass, PIIFinding, TextSpan } from "./piiNormalize.js";

type AllowlistTarget = "secret" | "match" | "line";

type AllowlistTargets = Readonly<Record<AllowlistTarget, string>>;

interface SecretAllowlist {
  readonly target: AllowlistTarget;
  readonly regexes: readonly RE2[];
  readonly stopwords: readonly string[];
}

interface SecretRule {
  readonly ruleId: string;
  readonly piiClass: PIIClass;
  readonly regex: RE2;
  readonly secretGroup: number;
  readonly entropyMin: number;
  readonly keywords: readonly string[];
  readonly allowlists: readonly SecretAllowlist[];
}

export interface SecretRuleSet {
  readonly rules: readonly SecretRule[];
  readonly globalAllowlist: SecretAllowlist;
  readonly uniqueKeywords: readonly string[];
}

let secretRuleSetCache: SecretRuleSet | null = null;

export function secretRuleSet(): SecretRuleSet {
  if (secretRuleSetCache === null) {
    secretRuleSetCache = compileSecretRuleSet(readVendoredJson("gitleaks_rules.json"));
  }
  return secretRuleSetCache;
}

function capturingGroupCount(pattern: string): number {
  const match = new RE2(pattern + "|").exec("");
  if (match === null) {
    throw new Error("an empty alternative always matches");
  }
  return match.length - 1;
}

function compileSecretAllowlist(source: unknown): SecretAllowlist {
  const allowlist = isRecord(source) ? source : {};
  const target = allowlist.regex_target || "secret";
  if (target !== "secret" && target !== "match" && target !== "line") {
    throw new Error(`unknown gitleaks allowlist regex target ${JSON.stringify(target)}`);
  }
  return {
    target,
    regexes: stringArray(allowlist.regexes, "allowlist regexes").map((pattern) => new RE2(pattern)),
    stopwords: stringArray(allowlist.stopwords, "allowlist stopwords"),
  };
}

function compileSecretRule(source: unknown): SecretRule {
  if (!isRecord(source) || typeof source.id !== "string" || typeof source.regex !== "string") {
    throw new Error("vendored gitleaks rule is missing its id or regex");
  }
  const ruleId = source.id;
  const secretGroup = source.secret_group;
  const entropyMin = source.entropy;
  if (typeof secretGroup !== "number" || !Number.isInteger(secretGroup) || secretGroup < 0) {
    throw new Error(`gitleaks rule ${ruleId} has an invalid secret group`);
  }
  if (typeof entropyMin !== "number") {
    throw new Error(`gitleaks rule ${ruleId} has no entropy threshold`);
  }
  const keywords = stringArray(source.keywords, `rule ${ruleId} keywords`);
  if (keywords.length === 0 || keywords.some((keyword) => keyword === "")) {
    throw new Error(`gitleaks rule ${ruleId} has no usable keywords to prefilter on`);
  }
  const regex = new RE2(source.regex, "gd");
  if (secretGroup > capturingGroupCount(source.regex)) {
    throw new Error(`gitleaks rule ${ruleId} secret group out of range`);
  }
  const allowlists = Array.isArray(source.allowlists)
    ? source.allowlists.map(compileSecretAllowlist)
    : [];
  const piiClass: PIIClass = ruleId === "aws-access-token" ? "AWS_KEY" : "SECRET";
  return { ruleId, piiClass, regex, secretGroup, entropyMin, keywords, allowlists };
}

function compileSecretRuleSet(source: unknown): SecretRuleSet {
  if (!isRecord(source) || !Array.isArray(source.rules) || source.rules.length === 0) {
    throw new Error("vendored gitleaks rules are empty");
  }
  const rules = source.rules.map(compileSecretRule);
  const uniqueKeywords = [...new Set(rules.flatMap((rule) => rule.keywords))];
  return {
    rules,
    globalAllowlist: compileSecretAllowlist(source.global_allowlist),
    uniqueKeywords,
  };
}

export function secretFindings(text: NormalizedText): PIIFinding[] {
  const ruleSet = secretRuleSet();
  const present = new Set(ruleSet.uniqueKeywords.filter((keyword) => text.lower.includes(keyword)));
  if (present.size === 0) {
    return [];
  }
  const findings: PIIFinding[] = [];
  for (const rule of ruleSet.rules) {
    if (!rule.keywords.some((keyword) => present.has(keyword))) {
      continue;
    }
    for (const match of text.text.matchAll(rule.regex)) {
      const [start, end] = secretSpan(match, rule.secretGroup);
      if (
        start >= end ||
        secretRejected(text.text, match, [start, end], rule, ruleSet.globalAllowlist)
      ) {
        continue;
      }
      findings.push(text.finding(rule.piiClass, start, end, "gitleaks:" + rule.ruleId));
    }
  }
  return findings;
}

function secretSpan(match: RegExpMatchArray, secretGroup: number): TextSpan {
  const indices = match.indices;
  if (indices === undefined) {
    throw new Error("secret rules must be compiled with the d flag");
  }
  if (secretGroup > 0) {
    return indices[secretGroup] ?? [-1, -1];
  }
  for (let group = 1; group < indices.length; group += 1) {
    const span = indices[group];
    if (span !== undefined && span[1] > span[0]) {
      return span;
    }
  }
  return indices[0];
}

function secretRejected(
  text: string,
  match: RegExpMatchArray,
  [start, end]: TextSpan,
  rule: SecretRule,
  globalAllowlist: SecretAllowlist,
): boolean {
  const secret = text.slice(start, end);
  if (rule.entropyMin > 0 && shannonEntropy(secret) <= rule.entropyMin) {
    return true;
  }
  const matchStart = match.index ?? 0;
  const matchEnd = matchStart + match[0].length;
  const lineStart = matchStart === 0 ? 0 : text.lastIndexOf("\n", matchStart - 1) + 1;
  const lineEnd = text.indexOf("\n", matchEnd);
  const targets: AllowlistTargets = {
    secret,
    match: match[0],
    line: text.slice(lineStart, lineEnd >= 0 ? lineEnd : text.length),
  };
  return (
    allowlistAllows(globalAllowlist, targets) ||
    rule.allowlists.some((allowlist) => allowlistAllows(allowlist, targets))
  );
}

function allowlistAllows(allowlist: SecretAllowlist, targets: AllowlistTargets): boolean {
  const targetText = targets[allowlist.target];
  if (allowlist.regexes.some((regex) => regex.test(targetText))) {
    return true;
  }
  const lowerSecret = targets.secret.toLowerCase();
  return allowlist.stopwords.some((stopword) => lowerSecret.includes(stopword));
}

export function shannonEntropy(value: string): number {
  if (value === "") {
    return 0;
  }
  const byteLength = Buffer.byteLength(value, "utf8");
  const counts = new Map<string, number>();
  for (const codePoint of value) {
    counts.set(codePoint, (counts.get(codePoint) ?? 0) + 1);
  }
  let entropy = 0;
  for (const count of counts.values()) {
    const frequency = count / byteLength;
    entropy -= frequency * Math.log2(frequency);
  }
  return entropy;
}
