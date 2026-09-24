import assert from "node:assert/strict";
import test from "node:test";

import { canonicalJson } from "../src/index.js";

test("keys sort by UTF-16 code units and output has no whitespace", () => {
  const value = { b: [1, { z: null, a: true }], a: "x", "\u{1F600}": 1, "\uffff": 2, "\u00e9": 3 };
  assert.equal(
    canonicalJson(value),
    '{"a":"x","b":[1,{"a":true,"z":null}],"\u00e9":3,"\u{1F600}":1,"\uffff":2}',
  );
});

test("numbers use ECMAScript formatting", () => {
  assert.equal(
    canonicalJson([1.5e-7, 1e21, 0.1, -0, 100, 812.25]),
    "[1.5e-7,1e+21,0.1,0,100,812.25]",
  );
});

test("strings use minimal escaping", () => {
  assert.equal(
    canonicalJson('line\n\t"q" \\ \u0001 \u007f'),
    '"line\\n\\t\\"q\\" \\\\ \\u0001 \u007f"',
  );
});

test("values outside JSON are rejected", () => {
  for (const invalid of [
    NaN,
    Infinity,
    -Infinity,
    undefined,
    () => 1,
    { a: undefined },
    new Date(0),
    1n,
    [, 1],
  ]) {
    assert.throws(() => canonicalJson(invalid), `${String(invalid)} should be rejected`);
  }
});

test("pathologically deep values are rejected instead of overflowing the stack", () => {
  let nested: unknown = 0;
  for (let depth = 0; depth < 1000; depth += 1) {
    nested = [nested];
  }
  assert.throws(() => canonicalJson(nested), RangeError);
});
