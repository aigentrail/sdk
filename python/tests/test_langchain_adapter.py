"""Standalone test for the langchain middleware adapter.

The langchain package is not a test dependency: AgentMiddleware and
ToolMessage are duck-typed stand-ins registered in sys.modules, and the
enforcer runs against a local HTTPServer. Runnable as
`python tests/test_langchain_adapter.py` or via pytest.
"""

import asyncio
import importlib.util
import json
import os
import sys
import threading
import types
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import SimpleNamespace

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.join(_HERE, "..", "gentrail")

_pkg = types.ModuleType("gentrail")
_pkg.__path__ = [_PKG_DIR]
sys.modules["gentrail"] = _pkg


def _load(name):
    spec = importlib.util.spec_from_file_location(
        f"gentrail.{name}", os.path.join(_PKG_DIR, name + ".py")
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules[f"gentrail.{name}"] = mod
    setattr(_pkg, name, mod)
    spec.loader.exec_module(mod)
    return mod


enforcement = _load("enforcement")
adapter = _load("langchain")


class FakeAgentMiddleware:
    pass


class FakeToolMessage:
    def __init__(self, content="", tool_call_id="", name="", status="success"):
        self.content = content
        self.tool_call_id = tool_call_id
        self.name = name
        self.status = status


_lc = types.ModuleType("langchain")
_lc_agents = types.ModuleType("langchain.agents")
_lc_middleware = types.ModuleType("langchain.agents.middleware")
_lc_middleware.AgentMiddleware = FakeAgentMiddleware
_lc_messages = types.ModuleType("langchain.messages")
_lc_messages.ToolMessage = FakeToolMessage
_lc.agents = _lc_agents
_lc_agents.middleware = _lc_middleware
_lc.messages = _lc_messages
sys.modules["langchain"] = _lc
sys.modules["langchain.agents"] = _lc_agents
sys.modules["langchain.agents.middleware"] = _lc_middleware
sys.modules["langchain.messages"] = _lc_messages


def _serve(verdict, gate_statuses=()):
    captured = {}
    statuses = list(gate_statuses)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, body):
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0))
            captured["body"] = json.loads(self.rfile.read(n))
            self._send(verdict)

        def do_GET(self):
            status = statuses[0] if len(statuses) == 1 else statuses.pop(0)
            self._send({"status": status})

        def log_message(self, *a):
            pass

    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, captured


def _middleware_for(verdict, gate_statuses=(), agent_id="reporter"):
    srv, captured = _serve(verdict, gate_statuses)
    enf = enforcement.PolicyEnforcer(f"http://127.0.0.1:{srv.server_address[1]}", "sk-test")
    return adapter.enforcement_middleware(enf, agent_id=agent_id), captured, srv


def _request():
    return SimpleNamespace(
        tool_call={
            "name": "run_sql",
            "args": {"database": "production", "sql": "DROP TABLE customers"},
            "id": "call_1",
        }
    )


def test_allow_calls_handler_and_sends_identity():
    mw, captured, srv = _middleware_for({"decision": "ALLOW"})
    result = mw.wrap_tool_call(_request(), lambda request: "TOOL_RAN")
    srv.shutdown()
    assert result == "TOOL_RAN"
    body = captured["body"]
    assert body["tool_name"] == "run_sql"
    assert body["tool_args"]["database"] == "production"
    assert body["agent_id"] == "reporter"
    assert body["request_id"] == "call_1"


def test_block_short_circuits_with_error_tool_message():
    mw, _, srv = _middleware_for(
        {"decision": "BLOCK", "rule": "destructive_sql_pre", "message": "BLOCKED: destructive SQL."}
    )
    ran = []
    result = mw.wrap_tool_call(_request(), lambda request: ran.append(request))
    srv.shutdown()
    assert ran == []
    assert isinstance(result, FakeToolMessage)
    assert result.status == "error"
    assert result.content == "BLOCKED: destructive SQL."
    assert result.tool_call_id == "call_1"
    assert result.name == "run_sql"


def test_gate_approved_runs_tool_async():
    enforcement.GATE_POLL_INTERVAL_SECONDS = 0.01

    async def handler(request):
        return "TOOL_RAN"

    mw, _, srv = _middleware_for(
        {"decision": "GATE", "message": "Hold on", "approval": {"status_url": "/api/v1/approvals/x"}},
        gate_statuses=["pending", "approved"],
    )
    result = asyncio.run(mw.awrap_tool_call(_request(), handler))
    srv.shutdown()
    assert result == "TOOL_RAN"


def test_gate_denied_cancels_sync():
    mw, _, srv = _middleware_for(
        {"decision": "GATE", "message": "Hold on", "approval": {"status_url": "/x"}},
        gate_statuses=["denied"],
    )
    result = mw.wrap_tool_call(_request(), lambda request: "TOOL_RAN")
    srv.shutdown()
    assert isinstance(result, FakeToolMessage)
    assert result.status == "error"
    assert result.content == "Hold on (approval denied)"


def test_gate_timeout_cancels_async():
    enforcement.GATE_POLL_INTERVAL_SECONDS = 0.01
    saved = os.environ.get("GENTRAIL_GATE_TIMEOUT_SECONDS")
    os.environ["GENTRAIL_GATE_TIMEOUT_SECONDS"] = "0.05"
    try:
        mw, _, srv = _middleware_for(
            {"decision": "GATE", "message": "Hold on", "approval": {"status_url": "/x"}},
            gate_statuses=["pending"],
        )
    finally:
        if saved is not None:
            os.environ["GENTRAIL_GATE_TIMEOUT_SECONDS"] = saved
        else:
            os.environ.pop("GENTRAIL_GATE_TIMEOUT_SECONDS", None)

    async def handler(request):
        return "TOOL_RAN"

    result = asyncio.run(mw.awrap_tool_call(_request(), handler))
    srv.shutdown()
    assert isinstance(result, FakeToolMessage)
    assert result.status == "error"
    assert result.content == "Hold on (approval timeout)"


def test_unconfigured_environment_raises():
    saved = {k: os.environ.pop(k, None) for k in ("GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_API_KEY")}
    try:
        adapter.enforcement_middleware()
    except RuntimeError as e:
        assert "GENTRAIL_DECIDE_ENDPOINT" in str(e)
    else:
        raise AssertionError("expected RuntimeError")
    finally:
        for k, val in saved.items():
            if val is not None:
                os.environ[k] = val


if __name__ == "__main__":
    test_allow_calls_handler_and_sends_identity()
    test_block_short_circuits_with_error_tool_message()
    test_gate_approved_runs_tool_async()
    test_gate_denied_cancels_sync()
    test_gate_timeout_cancels_async()
    test_unconfigured_environment_raises()
    print("ALL PASS")
