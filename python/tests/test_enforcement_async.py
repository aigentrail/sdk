"""Standalone test for the AsyncPolicyEnforcer.

Loads enforcement.py directly so it runs without the SDK's runtime deps
(pydantic, strands). Runnable as `python tests/test_enforcement_async.py` or
via pytest.
"""

import asyncio
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
AsyncPolicyEnforcer = _mod.AsyncPolicyEnforcer


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


def _serve_gets(responses: list) -> tuple[int, list]:
    log: list = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            log.append(self.path)
            body = responses[min(len(log) - 1, len(responses) - 1)]
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    port = srv.server_address[1]

    def run():
        for _ in range(len(responses) + 20):
            srv.handle_request()

    threading.Thread(target=run, daemon=True).start()
    return port, log


def test_decide_block_verdict_with_auth_and_payload():
    port, captured = _serve_once(
        {"decision": "BLOCK", "rule": "destructive_sql_pre", "message": "BLOCKED."}
    )
    enf = AsyncPolicyEnforcer(f"http://127.0.0.1:{port}", "sk-test-key")
    v = asyncio.run(enf.decide("run_sql", {"database": "production"}))
    assert v["decision"] == "BLOCK"
    assert v["rule"] == "destructive_sql_pre"
    assert captured["auth"] == "Bearer sk-test-key"
    assert captured["body"]["tool_name"] == "run_sql"
    assert captured["body"]["tool_args"]["database"] == "production"


def test_decide_fails_open_when_backend_unreachable():
    enf = AsyncPolicyEnforcer("http://127.0.0.1:1", "sk", timeout=0.5)
    assert asyncio.run(enf.decide("run_sql", {}))["decision"] == "ALLOW"


def test_decide_sends_caller_identity_when_given():
    port, captured = _serve_once({"decision": "ALLOW"})
    enf = AsyncPolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    asyncio.run(
        enf.decide(
            "run_sql",
            {"sql": "SELECT 1"},
            agent_id="agent-reporter",
            invocation_id="0af7651916cd43dd8448eb211c80319c",
            request_id="tooluse_abc123",
        )
    )
    body = captured["body"]
    assert body["agent_id"] == "agent-reporter"
    assert body["invocation_id"] == "0af7651916cd43dd8448eb211c80319c"
    assert body["request_id"] == "tooluse_abc123"


def test_from_env_requires_endpoint_and_key():
    saved = {k: os.environ.pop(k, None) for k in ("GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_API_KEY")}
    try:
        assert AsyncPolicyEnforcer.from_env() is None
        os.environ["GENTRAIL_DECIDE_ENDPOINT"] = "https://example.test"
        os.environ["GENTRAIL_API_KEY"] = "sk"
        assert AsyncPolicyEnforcer.from_env() is not None
    finally:
        for k, val in saved.items():
            if val is not None:
                os.environ[k] = val
            else:
                os.environ.pop(k, None)


def test_await_gate_polls_until_approved():
    _mod.GATE_POLL_INTERVAL_SECONDS = 0.01
    port, log = _serve_gets(
        [{"status": "pending"}, {"status": "pending"}, {"status": "approved"}]
    )
    enf = AsyncPolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    status = asyncio.run(enf.await_gate({"status_url": "/api/v1/approvals/x"}, timeout=5))
    assert status == "approved"
    assert len(log) >= 3
    assert log[0] == "/api/v1/approvals/x"


def test_await_gate_returns_denied():
    port, _ = _serve_gets([{"status": "denied"}])
    enf = AsyncPolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    assert asyncio.run(enf.await_gate({"status_url": "/x"}, timeout=5)) == "denied"


def test_await_gate_times_out_while_pending():
    _mod.GATE_POLL_INTERVAL_SECONDS = 0.01
    port, _ = _serve_gets([{"status": "pending"}])
    enf = AsyncPolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    assert asyncio.run(enf.await_gate({"status_url": "/x"}, timeout=0.05)) == "timeout"


def test_await_gate_fails_closed_without_status_url():
    enf = AsyncPolicyEnforcer("http://127.0.0.1:1", "sk")
    assert asyncio.run(enf.await_gate({})) == "timeout"


def test_await_gate_fails_closed_when_unreachable():
    enf = AsyncPolicyEnforcer("http://127.0.0.1:1", "sk", timeout=0.3)
    assert asyncio.run(enf.await_gate({"status_url": "/x"}, timeout=1)) == "timeout"


if __name__ == "__main__":
    test_decide_block_verdict_with_auth_and_payload()
    test_decide_fails_open_when_backend_unreachable()
    test_decide_sends_caller_identity_when_given()
    test_from_env_requires_endpoint_and_key()
    test_await_gate_polls_until_approved()
    test_await_gate_returns_denied()
    test_await_gate_times_out_while_pending()
    test_await_gate_fails_closed_without_status_url()
    test_await_gate_fails_closed_when_unreachable()
    print("ALL PASS")
