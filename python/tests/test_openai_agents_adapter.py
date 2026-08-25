"""Standalone test for the OpenAI Agents SDK adapter.

The openai-agents package is not a test dependency: the framework types the
factory constructs (ToolInputGuardrail, ToolGuardrailFunctionOutput) are
duck-typed stand-ins registered in sys.modules, and the enforcer runs against
a local HTTPServer. Runnable as `python tests/test_openai_agents_adapter.py`
or via pytest.
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
adapter = _load("openai_agents")


class FakeOutput:
    def __init__(self, behavior, message=""):
        self.behavior = behavior
        self.message = message

    @classmethod
    def allow(cls, output_info=None):
        return cls("allow")

    @classmethod
    def reject_content(cls, message, output_info=None):
        return cls("reject_content", message)


class FakeToolInputGuardrail:
    def __init__(self, guardrail_function, name=None):
        self.guardrail_function = guardrail_function
        self.name = name


_agents_pkg = types.ModuleType("agents")
_agents_tg = types.ModuleType("agents.tool_guardrails")
_agents_tg.ToolGuardrailFunctionOutput = FakeOutput
_agents_tg.ToolInputGuardrail = FakeToolInputGuardrail
_agents_pkg.tool_guardrails = _agents_tg
sys.modules["agents"] = _agents_pkg
sys.modules["agents.tool_guardrails"] = _agents_tg


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


def _guardrail_for(verdict, gate_statuses=()):
    srv, captured = _serve(verdict, gate_statuses)
    enf = enforcement.PolicyEnforcer(f"http://127.0.0.1:{srv.server_address[1]}", "sk-test")
    return adapter.enforcement_guardrail(enf), captured, srv


def _data():
    return SimpleNamespace(
        context=SimpleNamespace(
            tool_name="run_sql",
            tool_call_id="call_1",
            tool_arguments='{"database": "production", "sql": "DROP TABLE customers"}',
        ),
        agent=SimpleNamespace(name="reporter"),
    )


def _run(guardrail, data):
    return asyncio.run(guardrail.guardrail_function(data))


def test_call_facts_extracts_identity():
    name, args, call_id, agent = adapter._call_facts(_data())
    assert (name, call_id, agent) == ("run_sql", "call_1", "reporter")
    assert args["database"] == "production"


def test_call_facts_wraps_unparseable_arguments():
    data = SimpleNamespace(
        context=SimpleNamespace(tool_name="t", tool_call_id="c", tool_arguments="not json"),
        agent=None,
    )
    _, args, _, agent = adapter._call_facts(data)
    assert args == {"raw": "not json"}
    assert agent == ""


def test_allow_passes_through_and_sends_identity():
    guardrail, captured, srv = _guardrail_for({"decision": "ALLOW"})
    out = _run(guardrail, _data())
    srv.shutdown()
    assert out.behavior == "allow"
    body = captured["body"]
    assert body["tool_name"] == "run_sql"
    assert body["tool_args"]["database"] == "production"
    assert body["agent_id"] == "reporter"
    assert body["request_id"] == "call_1"


def test_block_rejects_with_rule_message():
    guardrail, _, srv = _guardrail_for(
        {"decision": "BLOCK", "rule": "destructive_sql_pre", "message": "BLOCKED: destructive SQL."}
    )
    out = _run(guardrail, _data())
    srv.shutdown()
    assert out.behavior == "reject_content"
    assert out.message == "BLOCKED: destructive SQL."


def test_gate_approved_proceeds():
    enforcement.GATE_POLL_INTERVAL_SECONDS = 0.01
    guardrail, _, srv = _guardrail_for(
        {"decision": "GATE", "message": "Hold on", "approval": {"status_url": "/api/v1/approvals/x"}},
        gate_statuses=["pending", "approved"],
    )
    out = _run(guardrail, _data())
    srv.shutdown()
    assert out.behavior == "allow"


def test_gate_denied_rejects():
    guardrail, _, srv = _guardrail_for(
        {"decision": "GATE", "message": "Hold on", "approval": {"status_url": "/x"}},
        gate_statuses=["denied"],
    )
    out = _run(guardrail, _data())
    srv.shutdown()
    assert out.behavior == "reject_content"
    assert out.message == "Hold on (approval denied)"


def test_unconfigured_environment_raises():
    saved = {k: os.environ.pop(k, None) for k in ("GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_API_KEY")}
    try:
        adapter.enforcement_guardrail()
    except RuntimeError as e:
        assert "GENTRAIL_DECIDE_ENDPOINT" in str(e)
    else:
        raise AssertionError("expected RuntimeError")
    finally:
        for k, val in saved.items():
            if val is not None:
                os.environ[k] = val


if __name__ == "__main__":
    test_call_facts_extracts_identity()
    test_call_facts_wraps_unparseable_arguments()
    test_allow_passes_through_and_sends_identity()
    test_block_rejects_with_rule_message()
    test_gate_approved_proceeds()
    test_gate_denied_rejects()
    test_unconfigured_environment_raises()
    print("ALL PASS")
