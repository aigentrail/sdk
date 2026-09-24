import assert from "node:assert/strict";

import {
  creditCardFindings,
  emailFindings,
  ibanFindings,
  phoneFindings,
  ssnFindings,
} from "./piiNumbers.js";
import { normalizeForPII, type NormalizedText, type PIIFinding } from "./piiNormalize.js";
import { secretFindings } from "./piiSecrets.js";

export { PII_CLASSES, type PIIClass, type PIIFinding } from "./piiNormalize.js";

const REDACTION_PASSES_MAX = 4;

const DETECTORS: readonly ((text: NormalizedText) => PIIFinding[])[] = [
  emailFindings,
  ssnFindings,
  creditCardFindings,
  ibanFindings,
  phoneFindings,
  secretFindings,
];

export function redactPII(field: string): string {
  let redacted = field;
  for (let pass = 0; pass < REDACTION_PASSES_MAX; pass += 1) {
    const next = redactPIIOnce(redacted);
    if (next === redacted) {
      return redacted;
    }
    redacted = next;
  }
  return redacted;
}

function redactPIIOnce(field: string): string {
  const findings = piiFindings(field).sort((a, b) => a.start - b.start || b.end - a.end);
  if (findings.length === 0) {
    return field;
  }
  const parts: string[] = [];
  let written = 0;
  for (const finding of findings) {
    if (finding.start < written) {
      written = Math.max(written, finding.end);
      continue;
    }
    parts.push(field.slice(written, finding.start), "[" + finding.piiClass + "]");
    written = finding.end;
  }
  parts.push(field.slice(written));
  return parts.join("");
}

export function piiFindings(field: string): PIIFinding[] {
  if (field === "") {
    return [];
  }
  const text = normalizeForPII(field);
  const findings = DETECTORS.flatMap((detect) => detect(text));
  for (const finding of findings) {
    assert.ok(finding.start >= 0, "pii finding starts before its field");
    assert.ok(finding.start < finding.end, "pii finding is empty");
    assert.ok(finding.end <= field.length, "pii finding ends past its field");
  }
  return findings;
}
