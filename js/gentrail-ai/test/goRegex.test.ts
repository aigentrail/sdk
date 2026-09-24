import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { goRegexToJs } from "../src/index.js";

function compile(pattern: string): RegExp {
  const translated = goRegexToJs(pattern);
  return new RegExp(translated.source, translated.flags);
}

interface VendoredAllowlist {
  regexes?: string[];
}

interface VendoredRules {
  global_allowlist: VendoredAllowlist;
  rules: { id: string; regex: string; allowlists: VendoredAllowlist[] }[];
}

function vendoredPatterns(): { label: string; pattern: string }[] {
  const location = new URL("../../data/gitleaks_rules.json", import.meta.url);
  const rules = JSON.parse(readFileSync(location, "utf8")) as VendoredRules;
  const patterns = (rules.global_allowlist.regexes ?? []).map((pattern) => ({
    label: "global allowlist",
    pattern,
  }));
  for (const rule of rules.rules) {
    patterns.push({ label: rule.id, pattern: rule.regex });
    for (const allowlist of rule.allowlists) {
      for (const pattern of allowlist.regexes ?? []) {
        patterns.push({ label: `${rule.id} allowlist`, pattern });
      }
    }
  }
  return patterns;
}

test("every vendored gitleaks regex translates and compiles without the u flag", () => {
  const patterns = vendoredPatterns();
  assert.ok(patterns.length >= 250, `only ${patterns.length} vendored patterns`);
  const failures: string[] = [];
  for (const { label, pattern } of patterns) {
    try {
      const regex = compile(pattern);
      assert.ok(!regex.unicode, `${label} compiled with the u flag`);
    } catch (err) {
      failures.push(`${label}: ${String(err)}`);
    }
  }
  assert.deepEqual(failures, []);
});

test("a leading flag directive becomes a native JS flag", () => {
  assert.deepEqual(goRegexToJs("(?i)abc"), { source: "abc", flags: "i" });
  assert.equal(goRegexToJs("(?is)a.c").flags, "is");
  assert.ok(compile("(?i)abc").test("xABCx"));
});

test("a mid-pattern (?i) is case-insensitive for the rest of the pattern only", () => {
  const regex = compile("^ab(?i)cd$");
  assert.ok(regex.test("abCD"));
  assert.ok(regex.test("abcd"));
  assert.ok(!regex.test("ABcd"));
});

test("a mid-pattern (?i) ends with its enclosing group", () => {
  const regex = compile("^(x(?i)y)z$");
  assert.ok(regex.test("xYz"));
  assert.ok(!regex.test("xyZ"));
  assert.ok(!regex.test("Xyz"));
});

test("a mid-pattern (?i) carries into later alternatives", () => {
  const regex = compile("^(?:a(?i)b|c)$");
  assert.ok(regex.test("aB"));
  assert.ok(regex.test("C"));
  assert.ok(!regex.test("AB"));
});

test("(?-i:...) stays case-sensitive inside a case-insensitive region", () => {
  const regex = compile("^x(?i)[a-c]+(?-i:acc)z$");
  assert.ok(regex.test("xABCaccZ"));
  assert.ok(!regex.test("xABCACCZ"));
  const leading = goRegexToJs("(?i)ab(?-i:cd)");
  assert.equal(leading.flags, "");
  assert.ok(compile("(?i)ab(?-i:cd)").test("ABcd"));
  assert.ok(!compile("(?i)ab(?-i:cd)").test("ABCD"));
});

test("scoped (?i:...) and character class ranges gain their other case", () => {
  const regex = compile("^(?i:[a-f0-9]{4})Z$");
  assert.ok(regex.test("aF09Z"));
  assert.ok(!regex.test("aF09z"));
  assert.ok(!compile("^(?i:[^a])$").test("A"));
});

test("dotAll groups match newlines while plain dots do not", () => {
  assert.ok(compile("^a(?s:.)b$").test("a\nb"));
  assert.ok(!compile("^a.b$").test("a\nb"));
  assert.ok(compile("^a.b$").test("a\rb"));
  assert.ok(compile("(?s)^a.b$").test("a\nb"));
});

test("RE2 escapes translate to their JS equivalents", () => {
  assert.ok(compile("end\\z").test("the end"));
  assert.ok(!compile("end\\z").test("the end\n"));
  assert.ok(compile("^(?P<word>\\w+)$").exec("hello")?.groups?.word === "hello");
  assert.ok(!compile("^\\s$").test("\v"));
  assert.ok(compile("^\\s$").test("\t"));
  assert.ok(!compile("^\\s$").test("\u00a0"));
  assert.ok(compile("^[[:alnum:]]+$").test("aZ09"));
  assert.ok(compile("^[\\s\\S-]+$").test("a -\n"));
  assert.ok(compile("^[[a]+$").test("[a["));
});

test("unsupported RE2 syntax fails loudly", () => {
  assert.throws(() => goRegexToJs("\\pL"));
  assert.throws(() => goRegexToJs("(?m)^a"));
  assert.throws(() => goRegexToJs("(a"));
  assert.throws(() => goRegexToJs("a)"));
});
