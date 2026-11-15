import assert from "node:assert/strict";
import { PolicyEnforcer, redactPII, guardTools } from "@gentrail/ai";

assert.equal(redactPII("reach jane@example.com"), "reach [EMAIL]");
const options = { endpoint: "http://127.0.0.1:1", apiKey: "key" };
const enforcer = new PolicyEnforcer(options);
assert.equal(
  (await enforcer.enforce("Read", {}, { toolId: "registered-read" })).allowed,
  false,
);
assert.equal((await enforcer.decide("Read", {})).decision, "BLOCK");
assert.throws(
  () => guardTools({ Read: { execute() {} } }, options),
  /registered tool ID/,
);
assert.equal(typeof guardTools, "function");
