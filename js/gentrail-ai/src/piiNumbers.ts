import assert from "node:assert/strict";

import RE2 from "re2";

import { isRecord, readVendoredJson } from "./piiData.js";
import {
  countAsciiDigits,
  findAllInSpans,
  type NormalizedText,
  type PIIFinding,
  type TextSpan,
} from "./piiNormalize.js";

const EMAIL = new RE2("[A-Za-z0-9._%+\\-]+@[A-Za-z0-9.\\-]+\\.[A-Za-z]{2,}", "g");
const FILE_EXTENSIONS_THAT_ARE_NOT_TLDS = new Set(
  "bmp css csv gif htm html ico jpeg jpg js json jsx md pdf png py svg tif tiff toml ts tsx txt webp xml yaml yml".split(
    " ",
  ),
);
const SSN_DASHED = new RE2("[0-9]{3}-[0-9]{2}-[0-9]{4}", "g");
const SSN_UNDELIMITED = new RE2("[0-9]{3} [0-9]{2} [0-9]{4}|[0-9]{9}", "g");
const SSN_CONTEXT_WORDS = ["ssn", "social security", "ss#", "ss #"];
const DIGIT_RUN = new RE2("[0-9](?:[ -]?[0-9])*", "g");
const CARD_DIGITS_MIN = 13;
const CARD_DIGITS_MAX = 19;
const PHONE_INTERNATIONAL = new RE2("\\+[0-9][0-9 ().-]{6,22}[0-9]", "g");
const PHONE_NATIONAL = new RE2("\\(?[0-9]{3}\\)?[ .-]?[0-9]{3}[ .-][0-9]{4}", "g");
const PHONE_DIGITS_MIN = 8;
const PHONE_DIGITS_MAX = 15;
const PHONE_CONTEXT_WORDS = [
  "phone",
  "tel",
  "call",
  "mobile",
  "cell",
  "fax",
  "sms",
  "whatsapp",
  "text me",
  "contact",
];
const IBAN_LENGTH_MIN = 15;
const IBAN_LENGTH_MAX = 34;

let ibanLengthByCountryCache: ReadonlyMap<string, number> | null = null;

export function emailFindings(text: NormalizedText): PIIFinding[] {
  const findings: PIIFinding[] = [];
  for (const [start, end] of findAllInSpans(EMAIL, text.lower, emailSpans(text.lower))) {
    const topLevelDomain = text.lower.slice(text.lower.lastIndexOf(".", end - 1) + 1, end);
    if (FILE_EXTENSIONS_THAT_ARE_NOT_TLDS.has(topLevelDomain)) {
      continue;
    }
    findings.push(text.finding("EMAIL", start, end, "email"));
  }
  return findings;
}

function isEmailChar(char: string): boolean {
  return (char >= "a" && char <= "z") || (char >= "0" && char <= "9") || "._%+-".includes(char);
}

function emailSpans(lower: string): TextSpan[] {
  const spans: TextSpan[] = [];
  let spanEnd = 0;
  let at = lower.indexOf("@");
  while (at >= 0) {
    if (at >= spanEnd) {
      let start = at;
      while (start > 0 && isEmailChar(lower[start - 1])) {
        start -= 1;
      }
      spanEnd = at + 1;
      while (spanEnd < lower.length && isEmailChar(lower[spanEnd])) {
        spanEnd += 1;
      }
      spans.push([start, spanEnd]);
    }
    at = lower.indexOf("@", at + 1);
  }
  return spans;
}

export function ssnFindings(text: NormalizedText): PIIFinding[] {
  const findings: PIIFinding[] = [];
  for (const [start, end] of findAllInSpans(SSN_DASHED, text.text, text.numericSpans)) {
    if (
      isolatedToken(text, start, end) &&
      validSSN(text.text.slice(start, end).replaceAll("-", ""))
    ) {
      findings.push(text.finding("SSN", start, end, "ssn_dashed"));
    }
  }
  for (const [start, end] of findAllInSpans(SSN_UNDELIMITED, text.text, text.numericSpans)) {
    if (!isolatedToken(text, start, end) || !text.contextBefore(start, SSN_CONTEXT_WORDS)) {
      continue;
    }
    if (validSSN(text.text.slice(start, end).replaceAll(" ", ""))) {
      findings.push(text.finding("SSN", start, end, "ssn_with_context"));
    }
  }
  return findings;
}

function isolatedToken(text: NormalizedText, start: number, end: number): boolean {
  const before = start - 1;
  const after = end;
  if (text.alphanumericAt(before) || text.alphanumericAt(after)) {
    return false;
  }
  const dashBefore = before >= 0 && text.text[before] === "-";
  const dashAfter = after < text.text.length && text.text[after] === "-";
  return !dashBefore && !dashAfter;
}

function validSSN(digits: string): boolean {
  assert.equal(digits.length, 9, "validSSN needs exactly nine digits");
  const area = digits.slice(0, 3);
  const group = digits.slice(3, 5);
  const serial = digits.slice(5);
  if (area === "000" || area === "666" || area[0] === "9") {
    return false;
  }
  return group !== "00" && serial !== "0000";
}

export function creditCardFindings(text: NormalizedText): PIIFinding[] {
  const findings: PIIFinding[] = [];
  for (const [runStart, runEnd] of findAllInSpans(DIGIT_RUN, text.text, text.numericSpans)) {
    const groups = digitGroups(text.text, runStart, runEnd);
    let first = 0;
    while (first < groups.length) {
      const last = longestCardSpan(text.text, groups, first);
      if (last === null) {
        first += 1;
        continue;
      }
      findings.push(
        text.finding("CREDIT_CARD", groups[first][0], groups[last][1], "credit_card_luhn"),
      );
      first = last + 1;
    }
  }
  return findings;
}

function digitGroups(text: string, start: number, end: number): TextSpan[] {
  const groups: TextSpan[] = [];
  let groupStart = start;
  for (let index = start; index < end; index += 1) {
    if (text[index] === " " || text[index] === "-") {
      groups.push([groupStart, index]);
      groupStart = index + 1;
    }
  }
  groups.push([groupStart, end]);
  return groups;
}

function longestCardSpan(text: string, groups: readonly TextSpan[], first: number): number | null {
  let digits = "";
  let last: number | null = null;
  for (let index = first; index < groups.length; index += 1) {
    digits += text.slice(groups[index][0], groups[index][1]);
    if (digits.length > CARD_DIGITS_MAX) {
      break;
    }
    if (digits.length >= CARD_DIGITS_MIN && validCardNumber(digits)) {
      last = index;
    }
  }
  return last;
}

function validCardNumber(digits: string): boolean {
  if (digits[0] < "2" || digits[0] > "6") {
    return false;
  }
  if ([...digits].every((digit) => digit === digits[0])) {
    return false;
  }
  return luhnValid(digits);
}

export function luhnValid(candidate: string): boolean {
  const digits = [...candidate]
    .filter((char) => char >= "0" && char <= "9")
    .map((char) => char.charCodeAt(0) - 48);
  if (digits.length < CARD_DIGITS_MIN || digits.length > CARD_DIGITS_MAX) {
    return false;
  }
  let total = 0;
  let double = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = digits[index];
    if (double) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    total += digit;
    double = !double;
  }
  return total % 10 === 0;
}

export function ibanLengthByCountry(): ReadonlyMap<string, number> {
  if (ibanLengthByCountryCache === null) {
    ibanLengthByCountryCache = parseIbanRegistry(readVendoredJson("iban_registry.json"));
  }
  return ibanLengthByCountryCache;
}

function parseIbanRegistry(registry: unknown): ReadonlyMap<string, number> {
  if (!isRecord(registry) || !isRecord(registry.length_by_country)) {
    throw new Error("vendored iban registry has no length_by_country table");
  }
  const lengths = new Map<string, number>();
  for (const [country, length] of Object.entries(registry.length_by_country)) {
    if (!/^[A-Z]{2}$/.test(country) || typeof length !== "number") {
      throw new Error(`implausible iban registry entry ${country}`);
    }
    if (!Number.isInteger(length) || length < IBAN_LENGTH_MIN || length > IBAN_LENGTH_MAX) {
      throw new Error(`implausible iban length ${country} ${length}`);
    }
    lengths.set(country, length);
  }
  if (lengths.size === 0) {
    throw new Error("vendored iban registry has no countries");
  }
  return lengths;
}

export function ibanFindings(text: NormalizedText): PIIFinding[] {
  const findings: PIIFinding[] = [];
  const lengths = ibanLengthByCountry();
  for (const start of ibanCandidateStarts(text.text)) {
    const length = lengths.get(text.text.slice(start, start + 2));
    if (length === undefined || text.alphanumericAt(start - 1)) {
      continue;
    }
    const { compact, end } = collectIban(text.text, start, length);
    if (compact.length !== length || text.alphanumericAt(end) || !ibanChecksumValid(compact)) {
      continue;
    }
    findings.push(text.finding("IBAN", start, end, "iban_mod97"));
  }
  return findings;
}

function isAsciiUpper(char: string | undefined): boolean {
  return char !== undefined && char >= "A" && char <= "Z";
}

function isAsciiDigit(char: string | undefined): boolean {
  return char !== undefined && char >= "0" && char <= "9";
}

function ibanCandidateStarts(text: string): number[] {
  const starts: number[] = [];
  for (let index = 0; index + 4 <= text.length; index += 1) {
    const countryCode = isAsciiUpper(text[index]) && isAsciiUpper(text[index + 1]);
    if (countryCode && isAsciiDigit(text[index + 2]) && isAsciiDigit(text[index + 3])) {
      starts.push(index);
    }
  }
  return starts;
}

function collectIban(
  text: string,
  start: number,
  length: number,
): { compact: string; end: number } {
  let compact = "";
  let end = start;
  for (let index = start; index < text.length && compact.length < length; index += 1) {
    const char = text[index];
    if (isAsciiDigit(char) || isAsciiUpper(char)) {
      compact += char;
      end = index + 1;
    } else if (char !== " " || index === start || text[index - 1] === " ") {
      break;
    }
  }
  return { compact, end };
}

function ibanChecksumValid(compact: string): boolean {
  const rearranged = compact.slice(4) + compact.slice(0, 4);
  let remainder = 0;
  for (const char of rearranged) {
    if (isAsciiDigit(char)) {
      remainder = (remainder * 10 + char.charCodeAt(0) - 48) % 97;
    } else if (isAsciiUpper(char)) {
      remainder = (remainder * 100 + char.charCodeAt(0) - 55) % 97;
    } else {
      return false;
    }
  }
  return remainder === 1;
}

export function phoneFindings(text: NormalizedText): PIIFinding[] {
  const findings: PIIFinding[] = [];
  for (const [start, end] of findAllInSpans(PHONE_INTERNATIONAL, text.text, text.numericSpans)) {
    const digitCount = countAsciiDigits(text.text.slice(start, end));
    if (text.alphanumericAt(start - 1) || text.digitAt(end)) {
      continue;
    }
    if (digitCount < PHONE_DIGITS_MIN || digitCount > PHONE_DIGITS_MAX) {
      continue;
    }
    findings.push(text.finding("PHONE", start, end, "phone_international"));
  }
  for (const [start, end] of findAllInSpans(PHONE_NATIONAL, text.text, text.numericSpans)) {
    if (isolatedToken(text, start, end) && text.contextBefore(start, PHONE_CONTEXT_WORDS)) {
      findings.push(text.finding("PHONE", start, end, "phone_national_with_context"));
    }
  }
  return findings;
}
