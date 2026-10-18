import importlib.metadata
import sys

import gentrail
from gentrail.pii import redact_pii

assert importlib.metadata.version("gentrail") == sys.argv[1]
assert redact_pii("reach jane@example.com") == "reach [EMAIL]"
assert not gentrail.PolicyEnforcer("http://127.0.0.1:1", "key").strict_admission
assert gentrail.PolicyEnforcer(
    "http://127.0.0.1:1", "key", strict_admission=True
).strict_admission
print(gentrail.__path__[0])
