"""Standalone test for the pre-call PolicyEnforcer.

Loads enforcement.py directly so it runs without the SDK's runtime deps
(pydantic, strands). Runnable as `python tests/test_enforcement.py` or via pytest.
"""

import importlib.util
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "enforcement", os.path.join(_HERE, "..", "gentrail", "enforcement.py")
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
PolicyEnforcer = _mod.PolicyEnforcer


def _serve_once(response: dict) -> tuple[int, dict]:
    captured: dict = {}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            captured["body"] = json.loads(self.rfile.read(n))
            captured["auth"] = self.headers.get("Authorization")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode())

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]
    threading.Thread(target=srv.handle_request, daemon=True).start()
    return port, captured


def test_block_verdict_with_auth_and_payload():
    port, captured = _serve_once(
        {"decision": "BLOCK", "rule": "destructive_sql_pre", "message": "BLOCKED: destructive SQL on production."}
    )
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk-test-key")
    v = enf.decide("run_sql", {"database": "production", "sql": "DROP TABLE customers"})
    assert v["decision"] == "BLOCK"
    assert v["rule"] == "destructive_sql_pre"
    assert captured["auth"] == "Bearer sk-test-key"
    assert captured["body"]["tool_name"] == "run_sql"
    assert captured["body"]["tool_args"]["database"] == "production"


def test_fails_open_when_backend_unreachable():
    enf = PolicyEnforcer("http://127.0.0.1:1", "sk", timeout=0.5)
    assert enf.decide("run_sql", {})["decision"] == "ALLOW"


def test_from_env_requires_endpoint_and_key():
    saved = {k: os.environ.pop(k, None) for k in ("GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_API_KEY")}
    try:
        assert PolicyEnforcer.from_env() is None
        os.environ["GENTRAIL_DECIDE_ENDPOINT"] = "https://example.test"
        os.environ["GENTRAIL_API_KEY"] = "sk"
        assert PolicyEnforcer.from_env() is not None
    finally:
        for k, val in saved.items():
            if val is not None:
                os.environ[k] = val
            else:
                os.environ.pop(k, None)


if __name__ == "__main__":
    test_block_verdict_with_auth_and_payload()
    test_fails_open_when_backend_unreachable()
    test_from_env_requires_endpoint_and_key()
    print("ALL PASS")
