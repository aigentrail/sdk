"""Standalone tests for create_governance_tracer's env gate.

Loads otel_exporter.py directly so it runs without the SDK's OTel/pydantic deps
(OTel is imported lazily, so the module loads on stdlib alone). Runnable as
`python tests/test_env_gate.py` or via pytest.
"""

import importlib.util
import logging
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "otel_exporter", os.path.join(_HERE, "..", "gentrail", "otel_exporter.py")
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

_ENV_KEYS = (
    "GENTRAIL_API_KEY",
    "AIGENTRAIL_API_KEY",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
)


def _create_with_env(env):
    """Run create_governance_tracer under exactly `env`, returning the result
    and any warning messages it logged."""
    records = []
    handler = logging.Handler()
    handler.emit = records.append
    _mod.logger.addHandler(handler)
    saved = {k: os.environ.pop(k, None) for k in _ENV_KEYS}
    os.environ.update(env)
    try:
        result = _mod.create_governance_tracer()
    finally:
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        os.environ.update({k: v for k, v in saved.items() if v is not None})
        _mod.logger.removeHandler(handler)
    warnings = [r.getMessage() for r in records if r.levelno >= logging.WARNING]
    return result, warnings


def test_bare_env_is_a_silent_opt_out():
    result, warnings = _create_with_env({})
    assert result is None
    assert warnings == []


def test_old_env_name_warns():
    result, warnings = _create_with_env({"AIGENTRAIL_API_KEY": "k"})
    assert result is None
    assert len(warnings) == 1
    assert "GENTRAIL_API_KEY" in warnings[0]


def test_endpoint_without_key_warns():
    result, warnings = _create_with_env(
        {"OTEL_EXPORTER_OTLP_ENDPOINT": "http://localhost:4318"}
    )
    assert result is None
    assert len(warnings) == 1
    assert "GENTRAIL_API_KEY" in warnings[0]


def test_key_set_passes_the_gate():
    original = _mod._try_import_otel
    _mod._try_import_otel = lambda: False
    try:
        result, warnings = _create_with_env({"GENTRAIL_API_KEY": "k"})
    finally:
        _mod._try_import_otel = original
    assert result is None
    assert len(warnings) == 1
    assert "not installed" in warnings[0]


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _fn()
            print(f"ok  {_name}")
    print("ENV GATE TESTS PASSED")
