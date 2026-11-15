import importlib.metadata
import sys

import gentrail
from gentrail.pii import redact_pii

assert importlib.metadata.version("gentrail") == sys.argv[1]
assert redact_pii("reach jane@example.com") == "reach [EMAIL]"
enforcer = gentrail.PolicyEnforcer(
    "http://127.0.0.1:1", "key", tool_ids={"Read": "registered-read"}
)
assert enforcer.decide("Read", {})["decision"] == "BLOCK"
assert enforcer.decide("unregistered", {})["decision"] == "BLOCK"
assert not enforcer.authorize_admission({"decision": "ALLOW", "outcome": "verified"})[0]
print(gentrail.__path__[0])
