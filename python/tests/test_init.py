"""init() wiring and the provider-attach vs fresh-provider paths.

create_governance_tracer must not clobber a TracerProvider the app already
configured: it attaches a span processor to it and scopes shutdown to that
processor alone. Only when no real provider exists does it install one.
Runnable as `python tests/test_init.py` or via pytest.
"""

import os
import sys
import types

try:
    from opentelemetry import trace as trace_api
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
    from opentelemetry.util._once import Once
except ImportError:  # without the project deps: skip, not fail
    import unittest

    if "pytest" in sys.modules:
        raise unittest.SkipTest("opentelemetry not installed")
    print("skipped: opentelemetry not installed")
    raise SystemExit(0)

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.abspath(os.path.join(_HERE, "..", "gentrail"))
if "gentrail" not in sys.modules:
    _pkg = types.ModuleType("gentrail")
    _pkg.__path__ = [_PKG_DIR]
    sys.modules["gentrail"] = _pkg
from gentrail import otel_exporter as _mod  # noqa: E402
assert _mod._try_import_otel(), "OTel packages must be installed for this test"

_ENV_KEYS = (
    "GENTRAIL_API_KEY",
    "GENTRAIL_DECIDE_ENDPOINT",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
)

UNREACHABLE_COLLECTOR = "http://127.0.0.1:9"


def _reset_global_provider():
    """The OTel global provider is set-once per process; tests for both paths
    need the same reset hook OTel's own test suite uses."""
    trace_api._TRACER_PROVIDER = None
    trace_api._TRACER_PROVIDER_SET_ONCE = Once()


class _env:
    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        self.saved = {k: os.environ.pop(k, None) for k in _ENV_KEYS}
        os.environ.update(self.values)

    def __exit__(self, *a):
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ.update({k: v for k, v in self.saved.items() if v is not None})


def test_fresh_provider_installed_when_none_exists():
    _reset_global_provider()
    with _env(GENTRAIL_API_KEY="k", OTEL_EXPORTER_OTLP_ENDPOINT=UNREACHABLE_COLLECTOR):
        gt = _mod.create_governance_tracer()
        assert gt is not None
        installed = trace_api.get_tracer_provider()
        assert isinstance(installed, TracerProvider)
        again = _mod.create_governance_tracer()
        assert again is not None
        assert trace_api.get_tracer_provider() is installed


def test_attach_keeps_app_provider_and_carries_governance_spans():
    _reset_global_provider()
    memory = InMemorySpanExporter()
    app_provider = TracerProvider()
    app_provider.add_span_processor(SimpleSpanProcessor(memory))
    trace_api.set_tracer_provider(app_provider)

    with _env(GENTRAIL_API_KEY="k", OTEL_EXPORTER_OTLP_ENDPOINT=UNREACHABLE_COLLECTOR):
        gt = _mod.create_governance_tracer()
        assert gt is not None
        assert trace_api.get_tracer_provider() is app_provider

        span = gt.start_invocation("ag1", "agent", "j1", "hi")
        gt.end_invocation(
            span, response="ok", total_tokens=0, tool_count=0, integrity_hash=""
        )
        names = [s.name for s in memory.get_finished_spans()]
        assert "governance.invocation" in names

        gt.shutdown()
        app_provider.get_tracer("app").start_span("app.after_shutdown").end()
        names = [s.name for s in memory.get_finished_spans()]
        assert "app.after_shutdown" in names


def test_auth_headers_default_to_bearer_and_yield_to_otel_env():
    with _env():
        assert _mod._auth_headers("sk-key") == {"Authorization": "Bearer sk-key"}
    with _env(OTEL_EXPORTER_OTLP_HEADERS="Authorization=Bearer%20tok"):
        assert _mod._auth_headers("sk-key") is None
    with _env(OTEL_EXPORTER_OTLP_TRACES_HEADERS="x-org=acme"):
        assert _mod._auth_headers("sk-key") is None


def _load_init_module():
    if "gentrail" not in sys.modules:
        pkg = types.ModuleType("gentrail")
        pkg.__path__ = [_PKG_DIR]
        sys.modules["gentrail"] = pkg
    import gentrail.init as init_mod

    return init_mod


def test_init_returns_handle_wired_from_env():
    init_mod = _load_init_module()
    with _env():
        handle = init_mod.init()
        assert handle.tracer is None
        assert handle.enforcer is None
        handle.flush()
        handle.shutdown()
    with _env(GENTRAIL_DECIDE_ENDPOINT="https://example.test", GENTRAIL_API_KEY="k"):
        handle = init_mod.init()
        assert handle.enforcer is not None
        assert handle.enforcer.url == "https://example.test/api/v1/decide"


def test_init_hook_needs_strands():
    init_mod = _load_init_module()
    try:
        import strands  # noqa: F401

        has_strands = True
    except ImportError:
        has_strands = False
    with _env():
        handle = init_mod.init()
        if has_strands:
            assert handle.hook() is not None
        else:
            try:
                handle.hook()
                raise AssertionError("hook() must surface the missing strands dep")
            except ImportError:
                pass


if __name__ == "__main__":
    test_fresh_provider_installed_when_none_exists()
    test_attach_keeps_app_provider_and_carries_governance_spans()
    test_auth_headers_default_to_bearer_and_yield_to_otel_env()
    test_init_returns_handle_wired_from_env()
    test_init_hook_needs_strands()
    print("ok")
