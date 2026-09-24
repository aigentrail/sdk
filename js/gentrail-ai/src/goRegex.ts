export interface TranslatedRegex {
  source: string;
  flags: string;
}

interface RegexFlagState {
  caseInsensitive: boolean;
  dotAll: boolean;
}

type CodeUnitRange = readonly [number, number];

const CODE_UNIT_MAX = 0xffff;
const ASCII_WHITESPACE_RANGES: readonly CodeUnitRange[] = [
  [0x09, 0x0a],
  [0x0c, 0x0d],
  [0x20, 0x20],
];
const ASCII_DIGIT_RANGES: readonly CodeUnitRange[] = [[0x30, 0x39]];
const ASCII_WORD_RANGES: readonly CodeUnitRange[] = [
  [0x30, 0x39],
  [0x41, 0x5a],
  [0x5f, 0x5f],
  [0x61, 0x7a],
];
const POSIX_CLASS_RANGES: Readonly<Record<string, readonly CodeUnitRange[]>> = {
  alnum: [
    [0x30, 0x39],
    [0x41, 0x5a],
    [0x61, 0x7a],
  ],
  alpha: [
    [0x41, 0x5a],
    [0x61, 0x7a],
  ],
  ascii: [[0x00, 0x7f]],
  blank: [
    [0x09, 0x09],
    [0x20, 0x20],
  ],
  cntrl: [
    [0x00, 0x1f],
    [0x7f, 0x7f],
  ],
  digit: ASCII_DIGIT_RANGES,
  graph: [[0x21, 0x7e]],
  lower: [[0x61, 0x7a]],
  print: [[0x20, 0x7e]],
  punct: [
    [0x21, 0x2f],
    [0x3a, 0x40],
    [0x5b, 0x60],
    [0x7b, 0x7e],
  ],
  space: [
    [0x09, 0x0d],
    [0x20, 0x20],
  ],
  upper: [[0x41, 0x5a]],
  word: ASCII_WORD_RANGES,
  xdigit: [
    [0x30, 0x39],
    [0x41, 0x46],
    [0x61, 0x66],
  ],
};
const SIMPLE_CONTROL_ESCAPES: Readonly<Record<string, number>> = {
  n: 0x0a,
  r: 0x0d,
  t: 0x09,
  f: 0x0c,
  v: 0x0b,
  a: 0x07,
};
const PASS_THROUGH_ESCAPES = new Set(["d", "D", "w", "W", "b", "B", "n", "r", "t", "f", "v"]);
const LEADING_FLAG_DIRECTIVE = /^\(\?([a-zA-Z]+)\)/;
const CASE_INSENSITIVITY_DISABLED_LATER = /\(\?[a-zA-Z]*-[a-zA-Z]*i[a-zA-Z]*[:)]/;
const QUANTIFIER_BRACES = /^\{\d+(?:,\d*)?\}/;
const GROUP_NAME = /^[A-Za-z_][A-Za-z0-9_]*>/;
const FLAG_GROUP = /^\(\?([a-zA-Z]*(?:-[a-zA-Z]+)?)([:)])/;

export function goRegexToJs(pattern: string): TranslatedRegex {
  const leading = LEADING_FLAG_DIRECTIVE.exec(pattern);
  const leadingFlags = leading
    ? applyFlagDirective({ caseInsensitive: false, dotAll: false }, leading[1])
    : null;
  const body = leading ? pattern.slice(leading[0].length) : pattern;
  const nativeCaseInsensitive =
    leadingFlags !== null &&
    leadingFlags.caseInsensitive &&
    !CASE_INSENSITIVITY_DISABLED_LATER.test(body);
  const initialState = leadingFlags ?? { caseInsensitive: false, dotAll: false };
  const source = translateRegexBody(body, initialState, nativeCaseInsensitive);
  let flags = "";
  if (nativeCaseInsensitive) {
    flags += "i";
  }
  if (initialState.dotAll) {
    flags += "s";
  }
  return { source, flags };
}

function applyFlagDirective(state: RegexFlagState, directive: string): RegexFlagState {
  const next = { ...state };
  let enable = true;
  for (const flag of directive) {
    if (flag === "-") {
      if (!enable) {
        throw new Error(`regex flag directive ${JSON.stringify(directive)} has two '-'`);
      }
      enable = false;
    } else if (flag === "i") {
      next.caseInsensitive = enable;
    } else if (flag === "s") {
      next.dotAll = enable;
    } else {
      throw new Error(
        `unsupported regex flag ${JSON.stringify(flag)} in ${JSON.stringify(directive)}`,
      );
    }
  }
  return next;
}

interface TranslationCursor {
  pattern: string;
  index: number;
  state: RegexFlagState;
  savedStates: RegexFlagState[];
  nativeCaseInsensitive: boolean;
  output: string[];
}

function translateRegexBody(
  pattern: string,
  initialState: RegexFlagState,
  nativeCaseInsensitive: boolean,
): string {
  const cursor: TranslationCursor = {
    pattern,
    index: 0,
    state: initialState,
    savedStates: [],
    nativeCaseInsensitive,
    output: [],
  };
  while (cursor.index < pattern.length) {
    translateNextToken(cursor);
  }
  if (cursor.savedStates.length !== 0) {
    throw new Error(`regex ${JSON.stringify(pattern)} has an unclosed group`);
  }
  return cursor.output.join("");
}

function translateNextToken(cursor: TranslationCursor): void {
  const char = cursor.pattern[cursor.index];
  if (char === "\\") {
    translateEscapeOutsideClass(cursor);
  } else if (char === "[") {
    translateCharacterClass(cursor);
  } else if (char === "(") {
    translateGroupOpen(cursor);
  } else if (char === ")") {
    const restored = cursor.savedStates.pop();
    if (restored === undefined) {
      throw new Error(`regex ${JSON.stringify(cursor.pattern)} has an unmatched ')'`);
    }
    cursor.state = restored;
    cursor.output.push(")");
    cursor.index += 1;
  } else if (char === ".") {
    cursor.output.push(cursor.state.dotAll ? "[\\s\\S]" : "[^\\n]");
    cursor.index += 1;
  } else if (char === "{") {
    translateBrace(cursor);
  } else if (char === "}") {
    cursor.output.push("\\}");
    cursor.index += 1;
  } else {
    const paired = pairsLetterCase(cursor) ? caseInsensitiveLetter(char.charCodeAt(0)) : null;
    cursor.output.push(paired ?? char);
    cursor.index += 1;
  }
}

function pairsLetterCase(cursor: TranslationCursor): boolean {
  return cursor.state.caseInsensitive && !cursor.nativeCaseInsensitive;
}

function translateBrace(cursor: TranslationCursor): void {
  const quantifier = QUANTIFIER_BRACES.exec(cursor.pattern.slice(cursor.index));
  if (quantifier) {
    cursor.output.push(quantifier[0]);
    cursor.index += quantifier[0].length;
    return;
  }
  cursor.output.push("\\{");
  cursor.index += 1;
}

function translateGroupOpen(cursor: TranslationCursor): void {
  const rest = cursor.pattern.slice(cursor.index);
  if (!rest.startsWith("(?")) {
    cursor.savedStates.push(cursor.state);
    cursor.output.push("(");
    cursor.index += 1;
    return;
  }
  const namedPrefix = rest.startsWith("(?P<") ? "(?P<" : rest.startsWith("(?<") ? "(?<" : null;
  if (namedPrefix !== null) {
    const name = GROUP_NAME.exec(rest.slice(namedPrefix.length));
    if (!name) {
      throw new Error(`unsupported regex group at ${JSON.stringify(rest.slice(0, 12))}`);
    }
    cursor.savedStates.push(cursor.state);
    cursor.output.push("(?<" + name[0]);
    cursor.index += namedPrefix.length + name[0].length;
    return;
  }
  const flagGroup = FLAG_GROUP.exec(rest);
  if (!flagGroup) {
    throw new Error(`unsupported regex group at ${JSON.stringify(rest.slice(0, 12))}`);
  }
  const nextState = applyFlagDirective(cursor.state, flagGroup[1]);
  if (nextState.caseInsensitive !== cursor.state.caseInsensitive && cursor.nativeCaseInsensitive) {
    throw new Error("regex disables case-insensitivity under a native i flag");
  }
  cursor.index += flagGroup[0].length;
  if (flagGroup[2] === ")") {
    cursor.state = nextState;
    return;
  }
  cursor.savedStates.push(cursor.state);
  cursor.state = nextState;
  cursor.output.push("(?:");
}

function translateEscapeOutsideClass(cursor: TranslationCursor): void {
  const escaped = cursor.pattern[cursor.index + 1];
  if (escaped === undefined) {
    throw new Error(`regex ${JSON.stringify(cursor.pattern)} ends with a lone backslash`);
  }
  if (escaped === "z" || escaped === "Z") {
    cursor.output.push("$");
    cursor.index += 2;
  } else if (escaped === "A") {
    cursor.output.push("^");
    cursor.index += 2;
  } else if (escaped === "s") {
    cursor.output.push("[\\t\\n\\f\\r ]");
    cursor.index += 2;
  } else if (escaped === "S") {
    cursor.output.push("[^\\t\\n\\f\\r ]");
    cursor.index += 2;
  } else if (escaped === "x") {
    const hex = readHexEscape(cursor.pattern, cursor.index);
    cursor.output.push(literalCodeUnit(hex.codeUnit, pairsLetterCase(cursor)));
    cursor.index += hex.length;
  } else if (PASS_THROUGH_ESCAPES.has(escaped)) {
    cursor.output.push("\\" + escaped);
    cursor.index += 2;
  } else if (/[A-Za-z0-9]/.test(escaped)) {
    throw new Error(`unsupported regex escape \\${escaped}`);
  } else {
    cursor.output.push("\\" + escaped);
    cursor.index += 2;
  }
}

function readHexEscape(
  pattern: string,
  backslashIndex: number,
): { codeUnit: number; length: number } {
  const afterX = pattern.slice(backslashIndex + 2);
  const braced = /^\{([0-9A-Fa-f]{1,4})\}/.exec(afterX);
  if (braced) {
    return { codeUnit: parseInt(braced[1], 16), length: 2 + braced[0].length };
  }
  const plain = /^[0-9A-Fa-f]{2}/.exec(afterX);
  if (!plain) {
    throw new Error(
      `unsupported regex hex escape at ${JSON.stringify(pattern.slice(backslashIndex, backslashIndex + 8))}`,
    );
  }
  return { codeUnit: parseInt(plain[0], 16), length: 4 };
}

function literalCodeUnit(codeUnit: number, pairLetterCase: boolean): string {
  const paired = pairLetterCase ? caseInsensitiveLetter(codeUnit) : null;
  return paired ?? escapeCodeUnit(codeUnit);
}

function caseInsensitiveLetter(codeUnit: number): string | null {
  const other = otherCaseAsciiLetter(codeUnit);
  if (other === null) {
    return null;
  }
  return "[" + String.fromCharCode(codeUnit) + String.fromCharCode(other) + "]";
}

function otherCaseAsciiLetter(codeUnit: number): number | null {
  if (codeUnit >= 0x61 && codeUnit <= 0x7a) {
    return codeUnit - 0x20;
  }
  if (codeUnit >= 0x41 && codeUnit <= 0x5a) {
    return codeUnit + 0x20;
  }
  return null;
}

function escapeCodeUnit(codeUnit: number): string {
  if (/[A-Za-z0-9]/.test(String.fromCharCode(codeUnit))) {
    return String.fromCharCode(codeUnit);
  }
  return "\\u" + codeUnit.toString(16).padStart(4, "0");
}

function translateCharacterClass(cursor: TranslationCursor): void {
  const pattern = cursor.pattern;
  let index = cursor.index + 1;
  const negated = pattern[index] === "^";
  if (negated) {
    index += 1;
  }
  const ranges: CodeUnitRange[] = [];
  let first = true;
  while (index < pattern.length && (pattern[index] !== "]" || first)) {
    first = false;
    const item = readClassItem(pattern, index);
    index = item.next;
    if (
      item.single !== null &&
      pattern[index] === "-" &&
      pattern[index + 1] !== "]" &&
      index + 1 < pattern.length
    ) {
      const upper = readClassItem(pattern, index + 1);
      if (upper.single === null || upper.single < item.single) {
        throw new Error(`invalid regex class range in ${JSON.stringify(pattern)}`);
      }
      ranges.push([item.single, upper.single]);
      index = upper.next;
      continue;
    }
    ranges.push(...item.ranges);
  }
  if (pattern[index] !== "]") {
    throw new Error(`regex ${JSON.stringify(pattern)} has an unclosed character class`);
  }
  const effective = pairsLetterCase(cursor) ? withOtherCaseRanges(ranges) : ranges;
  cursor.output.push("[" + (negated ? "^" : "") + effective.map(emitClassRange).join("") + "]");
  cursor.index = index + 1;
}

interface ClassItem {
  ranges: readonly CodeUnitRange[];
  single: number | null;
  next: number;
}

function readClassItem(pattern: string, index: number): ClassItem {
  const char = pattern[index];
  if (char === "[" && pattern[index + 1] === ":") {
    const close = pattern.indexOf(":]", index + 2);
    const name = close < 0 ? "" : pattern.slice(index + 2, close);
    const posix = POSIX_CLASS_RANGES[name];
    if (posix === undefined) {
      throw new Error(`unsupported POSIX class in ${JSON.stringify(pattern)}`);
    }
    return { ranges: posix, single: null, next: close + 2 };
  }
  if (char !== "\\") {
    const codeUnit = pattern.charCodeAt(index);
    return { ranges: [[codeUnit, codeUnit]], single: codeUnit, next: index + 1 };
  }
  return readClassEscape(pattern, index);
}

function readClassEscape(pattern: string, index: number): ClassItem {
  const escaped = pattern[index + 1];
  if (escaped === undefined) {
    throw new Error(`regex ${JSON.stringify(pattern)} ends with a lone backslash`);
  }
  const shorthand = shorthandClassRanges(escaped);
  if (shorthand !== null) {
    return { ranges: shorthand, single: null, next: index + 2 };
  }
  if (escaped === "x") {
    const hex = readHexEscape(pattern, index);
    return {
      ranges: [[hex.codeUnit, hex.codeUnit]],
      single: hex.codeUnit,
      next: index + hex.length,
    };
  }
  const control = SIMPLE_CONTROL_ESCAPES[escaped];
  if (control !== undefined) {
    return { ranges: [[control, control]], single: control, next: index + 2 };
  }
  if (/[A-Za-z0-9]/.test(escaped)) {
    throw new Error(`unsupported regex class escape \\${escaped}`);
  }
  const codeUnit = escaped.charCodeAt(0);
  return { ranges: [[codeUnit, codeUnit]], single: codeUnit, next: index + 2 };
}

function shorthandClassRanges(escaped: string): readonly CodeUnitRange[] | null {
  switch (escaped) {
    case "d":
      return ASCII_DIGIT_RANGES;
    case "D":
      return complementRanges(ASCII_DIGIT_RANGES);
    case "w":
      return ASCII_WORD_RANGES;
    case "W":
      return complementRanges(ASCII_WORD_RANGES);
    case "s":
      return ASCII_WHITESPACE_RANGES;
    case "S":
      return complementRanges(ASCII_WHITESPACE_RANGES);
    default:
      return null;
  }
}

function complementRanges(sortedDisjoint: readonly CodeUnitRange[]): CodeUnitRange[] {
  const complement: CodeUnitRange[] = [];
  let next = 0;
  for (const [low, high] of sortedDisjoint) {
    if (low > next) {
      complement.push([next, low - 1]);
    }
    next = high + 1;
  }
  if (next <= CODE_UNIT_MAX) {
    complement.push([next, CODE_UNIT_MAX]);
  }
  return complement;
}

function withOtherCaseRanges(ranges: readonly CodeUnitRange[]): CodeUnitRange[] {
  const paired: CodeUnitRange[] = [...ranges];
  for (const [low, high] of ranges) {
    const lowerLow = Math.max(low, 0x61);
    const lowerHigh = Math.min(high, 0x7a);
    if (lowerLow <= lowerHigh) {
      paired.push([lowerLow - 0x20, lowerHigh - 0x20]);
    }
    const upperLow = Math.max(low, 0x41);
    const upperHigh = Math.min(high, 0x5a);
    if (upperLow <= upperHigh) {
      paired.push([upperLow + 0x20, upperHigh + 0x20]);
    }
  }
  return paired;
}

function emitClassRange([low, high]: CodeUnitRange): string {
  if (low === high) {
    return escapeCodeUnit(low);
  }
  return escapeCodeUnit(low) + "-" + escapeCodeUnit(high);
}
