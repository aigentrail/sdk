import assert from "node:assert/strict";

export const PII_CLASSES = [
  "AWS_KEY",
  "CREDIT_CARD",
  "EMAIL",
  "IBAN",
  "PHONE",
  "SECRET",
  "SSN",
] as const;

export type PIIClass = (typeof PII_CLASSES)[number];

export interface PIIFinding {
  readonly piiClass: PIIClass;
  readonly start: number;
  readonly end: number;
  readonly detector: string;
}

export type TextSpan = readonly [number, number];

const DROPPED_CODE_POINTS = new Set([0x00ad, 0x200b, 0x200c, 0x200d, 0x2060, 0xfeff]);
const DASH_CODE_POINTS = new Set([
  0x2010, 0x2011, 0x2012, 0x2013, 0x2014, 0x2015, 0x2212, 0xfe58, 0xfe63, 0xff0d,
]);
const SPACE_SEPARATOR = /^\p{Zs}$/u;
const ASCII_ONLY = /^[\x00-\x7f]*$/;
const NUMERIC_SPAN = /[+(]?[0-9](?:[ .()\-]{0,2}[0-9])*/g;
const NUMERIC_SPAN_DIGITS_MIN = 8;
const CONTEXT_WINDOW_SIZE = 40;
const PLACEHOLDER_TOKEN = /\[(?:AWS_KEY|CREDIT_CARD|EMAIL|IBAN|PHONE|SECRET|SSN)\]/g;

export class NormalizedText {
  readonly text: string;
  readonly lower: string;
  readonly numericSpans: readonly TextSpan[];
  private readonly placeholderSpans: readonly TextSpan[];
  private readonly originOfIndex: readonly number[] | null;

  constructor(text: string, originOfIndex: readonly number[] | null) {
    assert.ok(
      originOfIndex === null || originOfIndex.length === text.length + 1,
      "pii offset map has the wrong size",
    );
    this.text = text;
    this.lower = lowerAscii(text);
    this.numericSpans = numericSpans(text);
    this.placeholderSpans = placeholderSpans(text);
    this.originOfIndex = originOfIndex;
  }

  finding(piiClass: PIIClass, start: number, end: number, detector: string): PIIFinding {
    assert.ok(start >= 0, "pii span starts before the normalized text");
    assert.ok(start < end, "pii span is empty");
    assert.ok(end <= this.text.length, "pii span ends past the normalized text");
    const originalStart = this.origin(start);
    const lastOriginInSpan = this.origin(end - 1);
    let originalEnd = this.origin(end);
    let nextIndex = end + 1;
    while (originalEnd <= lastOriginInSpan) {
      originalEnd = this.origin(nextIndex);
      nextIndex += 1;
    }
    return { piiClass, start: originalStart, end: originalEnd, detector };
  }

  digitAt(index: number): boolean {
    if (index < 0 || index >= this.text.length) {
      return false;
    }
    const char = this.text[index];
    return (char >= "0" && char <= "9") || this.insidePlaceholder(index);
  }

  alphanumericAt(index: number): boolean {
    if (index < 0 || index >= this.text.length) {
      return false;
    }
    const char = this.lower[index];
    const alphanumeric = (char >= "0" && char <= "9") || (char >= "a" && char <= "z");
    return alphanumeric || this.insidePlaceholder(index);
  }

  contextBefore(start: number, words: readonly string[]): boolean {
    const window = this.lower.slice(Math.max(0, start - CONTEXT_WINDOW_SIZE), start);
    return words.some((word) => window.includes(word));
  }

  private insidePlaceholder(index: number): boolean {
    let low = 0;
    let high = this.placeholderSpans.length;
    while (low < high) {
      const middle = (low + high) >>> 1;
      const [start, end] = this.placeholderSpans[middle];
      if (index < start) {
        high = middle;
      } else if (index >= end) {
        low = middle + 1;
      } else {
        return true;
      }
    }
    return false;
  }

  private origin(index: number): number {
    if (this.originOfIndex === null) {
      return index;
    }
    const origin = this.originOfIndex[index];
    assert.ok(origin !== undefined, "pii offset map lookup out of range");
    return origin;
  }
}

export function normalizeForPII(original: string): NormalizedText {
  if (ASCII_ONLY.test(original)) {
    return new NormalizedText(original, null);
  }
  const parts: string[] = [];
  const originOfIndex: number[] = [];
  let index = 0;
  while (index < original.length) {
    const codePoint = original.codePointAt(index);
    assert.ok(codePoint !== undefined, "code point lookup out of range");
    const width = codePoint > 0xffff ? 2 : 1;
    const folded = codePoint < 0x80 ? original[index] : foldCodePoint(codePoint);
    parts.push(folded);
    for (let unit = 0; unit < folded.length; unit += 1) {
      originOfIndex.push(index);
    }
    index += width;
  }
  originOfIndex.push(original.length);
  return new NormalizedText(parts.join(""), originOfIndex);
}

function foldCodePoint(codePoint: number): string {
  if (DROPPED_CODE_POINTS.has(codePoint)) {
    return "";
  }
  if (DASH_CODE_POINTS.has(codePoint)) {
    return "-";
  }
  const char = String.fromCodePoint(codePoint);
  if (SPACE_SEPARATOR.test(char)) {
    return " ";
  }
  return char.normalize("NFKC");
}

function lowerAscii(text: string): string {
  return text.replace(/[A-Z]/g, (char) => String.fromCharCode(char.charCodeAt(0) + 0x20));
}

function placeholderSpans(text: string): TextSpan[] {
  const spans: TextSpan[] = [];
  for (const match of text.matchAll(PLACEHOLDER_TOKEN)) {
    spans.push([match.index, match.index + match[0].length]);
  }
  return spans;
}

function numericSpans(text: string): TextSpan[] {
  const spans: TextSpan[] = [];
  for (const match of text.matchAll(NUMERIC_SPAN)) {
    if (countAsciiDigits(match[0]) >= NUMERIC_SPAN_DIGITS_MIN) {
      spans.push([match.index, match.index + match[0].length]);
    }
  }
  return spans;
}

export function countAsciiDigits(text: string): number {
  let count = 0;
  for (const char of text) {
    if (char >= "0" && char <= "9") {
      count += 1;
    }
  }
  return count;
}

export function findAllInSpans(
  pattern: RegExp,
  text: string,
  spans: readonly TextSpan[],
): TextSpan[] {
  assert.ok(pattern.global, "findAllInSpans needs a global regex");
  const matches: TextSpan[] = [];
  for (const [spanStart, spanEnd] of spans) {
    for (const match of text.slice(spanStart, spanEnd).matchAll(pattern)) {
      matches.push([spanStart + match.index, spanStart + match.index + match[0].length]);
    }
  }
  return matches;
}
