import assert from "node:assert/strict";
import test from "node:test";
import {
  argumentsHash,
  checkedReference,
  observationAttributes,
} from "../src/observationReference.js";
import { readSpecJson } from "./support.js";

test("argument hashes match the shared Go and Python vectors", () => {
  const vectors = readSpecJson("observation_vectors.json") as {
    arguments: string;
    sha256: string;
  }[];
  for (const vector of vectors) {
    assert.equal(argumentsHash(vector.arguments), vector.sha256);
  }
  assert.equal(argumentsHash("null"), argumentsHash("{}"));
});

test("receipts require exact identities and proposed arguments", () => {
  const request = { request_id: "request", invocation_id: "invocation", tool_args: { x: 1 } };
  const reference = {
    request_id: "request",
    invocation_id: "invocation",
    proposal_hash: "a".repeat(64),
    arguments_hash: argumentsHash('{"x":1}'),
  };
  assert.deepEqual(checkedReference(reference, request), reference);
  for (const field of Object.keys(reference)) {
    assert.equal(checkedReference({ ...reference, [field]: "invalid" }, request), undefined);
  }
  const attributes = observationAttributes(reference, '{"x":2}');
  assert.equal(attributes["aigentrail.decision.arguments_hash"], argumentsHash('{"x":2}'));
  assert.notEqual(attributes["aigentrail.decision.arguments_hash"], reference.arguments_hash);
  assert.deepEqual(observationAttributes(undefined, "invalid"), {});
});
