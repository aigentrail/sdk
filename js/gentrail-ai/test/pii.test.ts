import assert from "node:assert/strict";
import test from "node:test";

import { PII_CLASSES, piiFindings, redactPII } from "../src/index.js";
import { readSpecJson, seededRandom } from "./support.js";

interface ConformanceCase {
  name: string;
  fields: string[];
  want: string[];
}

interface ConformanceCorpus {
  classes: string[];
  cases: ConformanceCase[];
}

const PLACEHOLDER = /\[(AWS_KEY|CREDIT_CARD|EMAIL|IBAN|PHONE|SECRET|SSN)\]/g;

function placeholderClasses(text: string): string[] {
  return [...text.matchAll(PLACEHOLDER)].map((match) => match[1]);
}

test("redaction conforms to the shared Gentrail corpus", () => {
  const corpus = readSpecJson("pii_conformance.json") as ConformanceCorpus;
  assert.deepEqual(corpus.classes, [...PII_CLASSES]);
  assert.ok(corpus.cases.length > 0, "corpus has no cases");
  const failures: string[] = [];
  for (const conformanceCase of corpus.cases) {
    const found = new Set<string>();
    for (const field of conformanceCase.fields) {
      const redacted = redactPII(field);
      if (conformanceCase.want.length === 0 && redacted !== field) {
        failures.push(
          `${conformanceCase.name}: ${JSON.stringify(field)} -> ${JSON.stringify(redacted)}, want unchanged`,
        );
      }
      for (const piiClass of placeholderClasses(redacted)) {
        found.add(piiClass);
      }
    }
    const got = [...found].sort();
    if (JSON.stringify(got) !== JSON.stringify(conformanceCase.want)) {
      failures.push(
        `${conformanceCase.name}: placeholders ${JSON.stringify(got)}, want ${JSON.stringify(conformanceCase.want)}`,
      );
    }
  }
  assert.deepEqual(failures, []);
});

test("redactPII replaces each value with its class placeholder", () => {
  const cases: [string, string][] = [
    ["reach me at jane.doe@example.com please", "reach me at [EMAIL] please"],
    ["SSN 123-45-6789 on file", "SSN [SSN] on file"],
    ["SSN 123456789 on file", "SSN [SSN] on file"],
    ["key AKIAZ4QXN7P2LRT5WVKB leaked", "key [AWS_KEY] leaked"],
    ["card 4111111111111111 charged", "card [CREDIT_CARD] charged"],
    ["card 4111 1111 1111 1111 charged", "card [CREDIT_CARD] charged"],
    ["amex 378282246310005 ok", "amex [CREDIT_CARD] ok"],
    ["pay DE89370400440532013000 today", "pay [IBAN] today"],
    ["phone 555-123-4567", "phone [PHONE]"],
    ["token ghp_R8x2mQ9vL4kT7nB1cZ5wY3pH6jD0fG2sA9eK", "token [SECRET]"],
    ['{"email":"a@b.co","ssn":"111-22-3333"}', '{"email":"[EMAIL]","ssn":"[SSN]"}'],
    ["a@b.com and 123-45-6789", "[EMAIL] and [SSN]"],
    ["just a normal sentence with 42 items", "just a normal sentence with 42 items"],
    ["", ""],
  ];
  for (const [raw, want] of cases) {
    assert.equal(redactPII(raw), want, `redactPII(${JSON.stringify(raw)})`);
  }
});

test("redactPII leaves look-alikes untouched", () => {
  for (const lookAlike of [
    "order 4111111111111112 shipped",
    "ref 1234567890123456 pending",
    "ref 555-123-4567",
    "id 12345",
    "icon@2x.png",
    "api_key = $API_KEY",
    "key AKIAIOSFODNN7EXAMPLE",
  ]) {
    assert.equal(redactPII(lookAlike), lookAlike);
  }
});

test("findings report offsets in the original string", () => {
  const field = "ssn 123\u201145\u20116789 \u200bjane@x.io";
  const findings = piiFindings(field).sort((a, b) => a.start - b.start);
  assert.deepEqual(
    findings.map((finding) => [finding.piiClass, field.slice(finding.start, finding.end)]),
    [
      ["SSN", "123\u201145\u20116789"],
      ["EMAIL", "jane@x.io"],
    ],
  );
  const astral = "\u{1F600} mail a@b.com";
  const [email] = piiFindings(astral);
  assert.equal(astral.slice(email.start, email.end), "a@b.com");
});

test("redaction leaves nothing detectable", () => {
  for (const field of [
    "0@0.AA+000000000000000",
    "ssn 123-45-6789 and a@b.com 4111111111111111",
    'phone 555-123-4567 api_key = "q8Zr4TmN2vX7pL1kW9sB"',
  ]) {
    const redacted = redactPII(field);
    assert.deepEqual(
      piiFindings(redacted),
      [],
      `${JSON.stringify(field)} -> ${JSON.stringify(redacted)}`,
    );
  }
});

test("a placeholder blocks its neighbours like the value it replaced", () => {
  const chain = "0@0.AA+00000000+00000000+00000000+00000000";
  const redactedChain = redactPII(chain);
  assert.equal(redactedChain, "[EMAIL]+00000000+00000000+00000000+00000000");
  assert.deepEqual(piiFindings(redactedChain), []);
  assert.equal(redactPII("[EMAIL]+00000000"), "[EMAIL]+00000000");
  assert.equal(redactPII("[EMAIL] phone +44 20 7946 0958"), "[EMAIL] phone [PHONE]");
});

test("random fields redact to a fixpoint with findings inside the field", () => {
  const random = seededRandom(20260923);
  const alphabet = [
    ...'0123456789 -+().@AKIAZ_ssnphoneapi_key="[]\n',
    "\u2011",
    "\uff11",
    "\u200b",
  ];
  const pick = (count: number): number => Math.floor(random() * count);
  for (let iteration = 0; iteration < 3000; iteration += 1) {
    const length = pick(61);
    let field = "";
    for (let index = 0; index < length; index += 1) {
      field += alphabet[pick(alphabet.length)];
    }
    for (const finding of piiFindings(field)) {
      assert.ok(
        finding.start >= 0 && finding.start < finding.end && finding.end <= field.length,
        JSON.stringify(field),
      );
    }
    const redacted = redactPII(field);
    assert.deepEqual(
      piiFindings(redacted),
      [],
      `${JSON.stringify(field)} -> ${JSON.stringify(redacted)}`,
    );
  }
});
