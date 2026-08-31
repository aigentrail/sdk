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


def _serve_gets(responses: list) -> tuple[int, list]:
    """Serve a sequence of GET responses (the last one repeats). Returns
    (port, request_log) so a test can watch the hold's status resolve."""
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
        for _ in range(len(responses) + 5):
            srv.handle_request()

    threading.Thread(target=run, daemon=True).start()
    return port, log


def test_await_gate_returns_approved_when_hold_resolves():
    port, log = _serve_gets([{"status": "approved", "decided_by": "a@b.c"}])
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    assert enf.await_gate({"status_url": "/api/v1/approvals/x"}, timeout=5) == "approved"
    assert log and log[0] == "/api/v1/approvals/x"


def test_await_gate_polls_until_resolved():
    _mod.GATE_POLL_INTERVAL_SECONDS = 0.01
    port, log = _serve_gets(
        [{"status": "pending"}, {"status": "pending"}, {"status": "approved"}]
    )
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    assert enf.await_gate({"status_url": "/x"}, timeout=5) == "approved"
    assert len(log) >= 3


def test_await_gate_returns_denied():
    port, _ = _serve_gets([{"status": "denied"}])
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk")
    assert enf.await_gate({"status_url": "/x"}, timeout=5) == "denied"


def test_await_gate_fails_closed_without_status_url():
    enf = PolicyEnforcer("http://127.0.0.1:1", "sk")
    assert enf.await_gate({}) == "timeout"


def test_await_gate_fails_closed_when_unreachable():
    enf = PolicyEnforcer("http://127.0.0.1:1", "sk", timeout=0.3)
    assert enf.await_gate({"status_url": "/x"}, timeout=1) == "timeout"


def test_decide_sends_caller_identity_when_given():
    port, captured = _serve_once({"decision": "ALLOW"})
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk-test-key")
    enf.decide(
        "run_sql",
        {"sql": "SELECT 1"},
        agent_id="agent-reporter",
        invocation_id="0af7651916cd43dd8448eb211c80319c",
        request_id="tooluse_abc123",
    )
    body = captured["body"]
    assert body["agent_id"] == "agent-reporter"
    assert body["invocation_id"] == "0af7651916cd43dd8448eb211c80319c"
    assert body["request_id"] == "tooluse_abc123"


def test_decide_omits_identity_fields_when_absent():
    port, captured = _serve_once({"decision": "ALLOW"})
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk-test-key")
    enf.decide("run_sql", {})
    body = captured["body"]
    assert "agent_id" not in body
    assert "invocation_id" not in body
    # The backend requires a retry identity, so a bare call synthesizes one.
    assert body["request_id"]


def test_decide_defaults_invocation_id_to_the_ambient_trace():
    """The backend refuses a BLOCK/GATE record it cannot join to a trace, so a
    caller already inside a recording span should not pass the id by hand."""
    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
    except ImportError:
        return
    trace.set_tracer_provider(TracerProvider())
    port, captured = _serve_once({"decision": "ALLOW"})
    enf = PolicyEnforcer(f"http://127.0.0.1:{port}", "sk-test-key")
    with trace.get_tracer(__name__).start_as_current_span("invocation") as span:
        want = format(span.get_span_context().trace_id, "032x")
        enf.decide("run_sql", {})
    assert captured["body"]["invocation_id"] == want


class _FakeEnforcer:
    def __init__(self, verdict, gate_status="approved"):
        self.verdict = verdict
        self.gate_status = gate_status
        self.decide_kwargs = None

    def decide(self, tool_name, tool_args, **kwargs):
        self.decide_kwargs = {"tool_name": tool_name, "tool_args": tool_args, **kwargs}
        return self.verdict

    def await_gate(self, approval):
        return self.gate_status


def test_enforce_allow_forwards_identity():
    fake = _FakeEnforcer({"decision": "ALLOW"})
    allowed, message = _mod.enforce(
        fake, "run_sql", {"sql": "SELECT 1"}, agent_id="a1", invocation_id="t1", request_id="r1"
    )
    assert (allowed, message) == (True, "")
    assert fake.decide_kwargs["agent_id"] == "a1"
    assert fake.decide_kwargs["invocation_id"] == "t1"
    assert fake.decide_kwargs["request_id"] == "r1"


def test_enforce_block_uses_fallback_message_without_backend_message():
    fake = _FakeEnforcer({"decision": "BLOCK", "rule": "r1"})
    assert _mod.enforce(fake, "run_sql", {}) == (False, "BLOCK by policy r1")


def test_enforce_gate_denied_appends_status():
    fake = _FakeEnforcer(
        {"decision": "GATE", "rule": "r1", "message": "Hold on", "approval": {"status_url": "/x"}},
        gate_status="denied",
    )
    assert _mod.enforce(fake, "run_sql", {}) == (False, "Hold on (approval denied)")


def test_enforce_gate_approved_allows():
    fake = _FakeEnforcer(
        {"decision": "GATE", "message": "Hold on", "approval": {"status_url": "/x"}}
    )
    assert _mod.enforce(fake, "run_sql", {}) == (True, "")


if __name__ == "__main__":
    test_block_verdict_with_auth_and_payload()
    test_fails_open_when_backend_unreachable()
    test_from_env_requires_endpoint_and_key()
    test_await_gate_returns_approved_when_hold_resolves()
    test_await_gate_polls_until_resolved()
    test_await_gate_returns_denied()
    test_await_gate_fails_closed_without_status_url()
    test_await_gate_fails_closed_when_unreachable()
    test_decide_sends_caller_identity_when_given()
    test_decide_omits_identity_fields_when_absent()
    test_decide_defaults_invocation_id_to_the_ambient_trace()
    test_enforce_allow_forwards_identity()
    test_enforce_block_uses_fallback_message_without_backend_message()
    test_enforce_gate_denied_appends_status()
    test_enforce_gate_approved_allows()
    print("ALL PASS")
