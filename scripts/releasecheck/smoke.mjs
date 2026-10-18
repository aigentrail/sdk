import assert from "node:assert/strict";
import { PolicyEnforcer, redactPII, guardTools } from "@gentrail/ai";

assert.equal(redactPII("reach jane@example.com"), "reach [EMAIL]");
const options = { endpoint: "http://127.0.0.1:1", apiKey: "key" };
assert.equal(new PolicyEnforcer(options).strictAdmission, false);
assert.equal(
  new PolicyEnforcer({ ...options, strictAdmission: true }).strictAdmission,
  true,
);
assert.equal(typeof guardTools, "function");
