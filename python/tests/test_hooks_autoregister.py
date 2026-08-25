"""The hook emits AGENT_REGISTERED on the first invocation per agent_id.

Consumers used to hand-write event_store.append(AgentEvent(...AGENT_REGISTERED))
after building each agent; the hook now folds that in, idempotent per hook
instance. Runs without strands or pydantic installed by stubbing just enough of
both (CI installs neither). Runnable as
`python tests/test_hooks_autoregister.py` or via pytest.
"""

import json
import os
import sys
import types

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.abspath(os.path.join(_HERE, "..", "gentrail"))


def _install_pydantic_stub():
    mod = types.ModuleType("pydantic")

    class _FieldSpec:
        def __init__(self, default=None, default_factory=None):
            self.default = default
            self.default_factory = default_factory

    def Field(default=None, **kwargs):
        return _FieldSpec(default, kwargs.get("default_factory"))

    class BaseModel:
        def __init__(self, **kwargs):
            for name in getattr(type(self), "__annotations__", {}):
                if name in kwargs:
                    setattr(self, name, kwargs[name])
                    continue
                default = getattr(type(self), name, None)
                if isinstance(default, _FieldSpec):
                    default = (
                        default.default_factory()
                        if default.default_factory
                        else default.default
                    )
                setattr(self, name, default)

        def model_dump_json(self, exclude=None):
            exclude = exclude or set()
            return json.dumps(
                {k: v for k, v in self.__dict__.items() if k not in exclude},
                default=str,
            )

    mod.Field = Field
    mod.BaseModel = BaseModel
    sys.modules["pydantic"] = mod


def _install_strands_stub():
    strands = types.ModuleType("strands")
    hooks = types.ModuleType("strands.hooks")
    events = types.ModuleType("strands.hooks.events")

    class HookProvider:
        pass

    class HookRegistry:
        def __init__(self):
            self.callbacks = []

        def add_callback(self, event_type, callback):
            self.callbacks.append((event_type, callback))

    hooks.HookProvider = HookProvider
    hooks.HookRegistry = HookRegistry
    for name in (
        "AfterInvocationEvent",
        "AfterModelCallEvent",
        "AfterToolCallEvent",
        "BeforeInvocationEvent",
        "BeforeModelCallEvent",
        "BeforeToolCallEvent",
    ):
        setattr(events, name, type(name, (), {}))
    hooks.events = events
    strands.hooks = hooks
    sys.modules["strands"] = strands
    sys.modules["strands.hooks"] = hooks
    sys.modules["strands.hooks.events"] = events


def _ensure(module_name, installer):
    try:
        __import__(module_name)
    except ImportError:
        installer()


_ensure("pydantic", _install_pydantic_stub)
_ensure("strands.hooks.events", _install_strands_stub)

if "gentrail" not in sys.modules:
    _pkg = types.ModuleType("gentrail")
    _pkg.__path__ = [_PKG_DIR]
    sys.modules["gentrail"] = _pkg

import gentrail.event_normalizer as en  # noqa: E402
import gentrail.evidence_ledger as el  # noqa: E402
import gentrail.hooks as hooks_mod  # noqa: E402


def _fresh_hook():
    saved = {
        k: os.environ.pop(k, None)
        for k in ("GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_API_KEY")
    }
    try:
        hook = hooks_mod.GentrailGovernanceHook(
            event_store_instance=en.EventStore(),
            ledger=el.EvidenceLedger(),
            otel_tracer=None,
        )
    finally:
        os.environ.update({k: v for k, v in saved.items() if v is not None})
    return hook


def _agent(agent_id="agent-1", **extra):
    return types.SimpleNamespace(agent_id=agent_id, name="Reporter", **extra)


def _invoke(hook, agent):
    hook.capture_invocation_start(types.SimpleNamespace(agent=agent, messages=[]))


def _registrations(hook):
    return [
        e
        for e in hook.events.get_all()
        if e.event_type == en.EventType.AGENT_REGISTERED
    ]


def test_first_invocation_registers_with_tools_and_model():
    hook = _fresh_hook()
    agent = _agent(
        tool_names=["run_sql", "report_status"],
        model=types.SimpleNamespace(config={"model_id": "m-1"}),
    )
    _invoke(hook, agent)
    events = hook.events.get_all()
    assert events[0].event_type == en.EventType.AGENT_REGISTERED
    assert events[1].event_type == en.EventType.INVOCATION_START
    assert events[0].payload == {
        "agent_name": "Reporter",
        "tier": "T4",
        "tools": ["run_sql", "report_status"],
        "model": "m-1",
    }


def test_second_invocation_does_not_register_again():
    hook = _fresh_hook()
    agent = _agent(tool_names=["run_sql"])
    _invoke(hook, agent)
    _invoke(hook, agent)
    assert len(_registrations(hook)) == 1


def test_registration_tolerates_missing_tools_and_model():
    hook = _fresh_hook()
    _invoke(hook, _agent())
    registered = _registrations(hook)
    assert len(registered) == 1
    assert registered[0].payload == {"agent_name": "Reporter", "tier": "T4"}


def test_each_agent_id_registers_once_per_hook():
    hook = _fresh_hook()
    _invoke(hook, _agent("agent-1"))
    _invoke(hook, _agent("agent-2"))
    _invoke(hook, _agent("agent-1"))
    assert [e.agent_id for e in _registrations(hook)] == ["agent-1", "agent-2"]


if __name__ == "__main__":
    test_first_invocation_registers_with_tools_and_model()
    test_second_invocation_does_not_register_again()
    test_registration_tolerates_missing_tools_and_model()
    test_each_agent_id_registers_once_per_hook()
    print("ok")
