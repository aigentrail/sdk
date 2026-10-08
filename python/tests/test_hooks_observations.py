import importlib
import importlib.util
import json
import pathlib
import sys
import types
from types import SimpleNamespace

root = pathlib.Path(__file__).resolve().parents[1]
package = types.ModuleType("gentrail")
package.__path__ = [str(root / "gentrail")]
sys.modules["gentrail"] = package
if importlib.util.find_spec("strands") is None:
    strands = types.ModuleType("strands")
    strands.__path__ = []
    strands_hooks = types.ModuleType("strands.hooks")
    strands_hooks.HookProvider = object
    strands_hooks.HookRegistry = object
    events = types.ModuleType("strands.hooks.events")
    for name in [
        "AfterInvocationEvent",
        "AfterModelCallEvent",
        "AfterToolCallEvent",
        "BeforeInvocationEvent",
        "BeforeModelCallEvent",
        "BeforeToolCallEvent",
    ]:
        setattr(events, name, type(name, (), {}))
    sys.modules.update(
        {
            "strands": strands,
            "strands.hooks": strands_hooks,
            "strands.hooks.events": events,
        }
    )
hooks = importlib.import_module("gentrail.hooks")
observation = importlib.import_module("gentrail.observation_reference")


class Enforcer:
    def __init__(self, decision="ALLOW", gate_status="approved"):
        self.decision = decision
        self.gate_status = gate_status

    def decide(self, name, args, **identity):
        reference = observation.DecisionReference(
            identity["request_id"] or "generated",
            identity["invocation_id"],
            "a" * 64,
            observation.arguments_hash(json.dumps(args)),
        )
        return dict(
            decision=self.decision, outcome="verified", observation_reference=reference
        )

    def await_gate(self, approval):
        return self.gate_status


class Tracer:
    def __init__(self):
        self.calls = []

    def record_tool_call(self, parent, **call):
        self.calls.append(call)


class Span:
    def get_span_context(self):
        return SimpleNamespace(trace_id=42)


def event(identity, args=None, cancel_message=None):
    return SimpleNamespace(
        agent=SimpleNamespace(agent_id="agent", name="Agent"),
        tool_use={"toolUseId": identity, "name": "send", "input": args or {}},
        result={"content": [{"text": "ok"}]},
        cancel_tool=False,
        selected_tool=object(),
        cancel_message=cancel_message,
    )


def test_results_keep_each_call_reference_and_full_arguments():
    tracer = Tracer()
    now = [1.0]
    hook = hooks.GentrailGovernanceHook(
        otel_tracer=tracer, enforcer=Enforcer(), clock=lambda: now[0]
    )
    hook._invocation_span = Span()
    first = event("first", {"padding": "x" * 5000})
    second = event("second", {"x": 2})
    hook.capture_tool_call_start(first)
    now[0] = 2.0
    hook.capture_tool_call_start(second)
    now[0] = 3.0
    hook.capture_tool_result(second)
    hook.capture_tool_result(first)
    assert [call["decision_reference"].request_id for call in tracer.calls] == [
        "second",
        "first",
    ]
    assert len(tracer.calls[1]["args"]) > 5000
    assert [call["duration_ms"] for call in tracer.calls] == [1000, 2000]
    assert hook._tool_call_count == 2
    assert not hook._pending_tool_calls


def test_cancelled_calls_never_emit_execution_observations():
    for decision, status in [
        ("BLOCK", "approved"),
        ("GATE", "denied"),
        ("GATE", "expired"),
    ]:
        tracer = Tracer()
        hook = hooks.GentrailGovernanceHook(
            otel_tracer=tracer, enforcer=Enforcer(decision, status)
        )
        hook._invocation_span = Span()
        call = event("cancelled")
        hook.capture_tool_call_start(call)
        assert call.cancel_tool
        hook.capture_tool_result(call)
        assert tracer.calls == []
        assert hook._tool_call_count == 0
    tracer = Tracer()
    hook = hooks.GentrailGovernanceHook(otel_tracer=tracer, enforcer=Enforcer())
    hook._invocation_span = Span()
    call = event("other-hook", cancel_message="cancelled elsewhere")
    hook.capture_tool_call_start(call)
    hook.capture_tool_result(call)
    assert tracer.calls == []


def test_pending_receipts_are_bounded_and_missing_receipts_remain_unlinked():
    tracer = Tracer()
    hook = hooks.GentrailGovernanceHook(otel_tracer=tracer, enforcer=Enforcer())
    hook._invocation_span = Span()
    for index in range(hooks.TOOL_CALLS_PENDING_MAX + 1):
        hook.capture_tool_call_start(event(str(index)))
    assert len(hook._pending_tool_calls) == hooks.TOOL_CALLS_PENDING_MAX
    hook.capture_tool_result(event("0"))
    assert tracer.calls[0]["decision_reference"] is None
    call = event(None)
    hook.capture_tool_call_start(call)
    hook.capture_tool_result(call)
    assert tracer.calls[1]["decision_reference"] is None


if __name__ == "__main__":
    test_results_keep_each_call_reference_and_full_arguments()
    test_cancelled_calls_never_emit_execution_observations()
    test_pending_receipts_are_bounded_and_missing_receipts_remain_unlinked()
