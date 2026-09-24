"""GentrailSpanProcessor redacts recognized GenAI attributes before export.

Redaction happens on a per-span copy inside the wrapping exporter, so the
Gentrail pipeline never sees the raw value while the app's own exporters keep
the untouched span. Runs against the real OTel SDK with an in-memory exporter.
Runnable as `python tests/test_processor.py` or via pytest.
"""

import os
import sys
import types

try:
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
except ImportError:  # without the project deps: skip, not fail
    import unittest

    if "pytest" in sys.modules:
        raise unittest.SkipTest("opentelemetry not installed")
    print("skipped: opentelemetry not installed")
    raise SystemExit(0)

_HERE = os.path.dirname(os.path.abspath(__file__))
_PKG_DIR = os.path.abspath(os.path.join(_HERE, "..", "gentrail"))


def _load_processor_module():
    if "gentrail" not in sys.modules:
        pkg = types.ModuleType("gentrail")
        pkg.__path__ = [_PKG_DIR]
        sys.modules["gentrail"] = pkg
    import gentrail.processor as processor_mod

    return processor_mod


_processor_mod = _load_processor_module()
GentrailSpanProcessor = _processor_mod.GentrailSpanProcessor
instrument = _processor_mod.instrument

_ENV_KEYS = (
    "GENTRAIL_API_KEY",
    "GENTRAIL_REDACT_PII",
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "OTEL_EXPORTER_OTLP_HEADERS",
    "OTEL_EXPORTER_OTLP_TRACES_HEADERS",
)

UNREACHABLE_COLLECTOR = "http://127.0.0.1:9"


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


def _pipeline(redact=True, extra_processor=None):
    memory = InMemorySpanExporter()
    provider = TracerProvider()
    if extra_processor is not None:
        provider.add_span_processor(extra_processor)
    provider.add_span_processor(GentrailSpanProcessor(exporter=memory, redact=redact))
    return provider, memory


def _emit(provider, attributes):
    tracer = provider.get_tracer("app")
    with tracer.start_as_current_span("chat gpt-4o") as span:
        for key, value in attributes.items():
            span.set_attribute(key, value)
    provider.force_flush()


def test_recognized_attrs_leave_pipeline_redacted():
    provider, memory = _pipeline()
    _emit(
        provider,
        {
            "gen_ai.output.messages": "pay with card 4111111111111111",
            "ai.prompt.messages": "email jane@acme.com",
            "input.value": "SSN 123-45-6789",
            "gen_ai.request.model": "gpt-4o",
        },
    )
    attrs = dict(memory.get_finished_spans()[0].attributes)
    assert attrs["gen_ai.output.messages"] == "pay with card [CREDIT_CARD]"
    assert attrs["ai.prompt.messages"] == "email [EMAIL]"
    assert attrs["input.value"] == "SSN [SSN]"
    assert attrs["gen_ai.request.model"] == "gpt-4o"
    assert attrs["aigentrail.redaction.applied"] is True


def test_non_genai_spans_never_leave_the_process():
    for redact in (True, False):
        provider, memory = _pipeline(redact=redact)
        _emit(provider, {"db.statement": "SELECT owner FROM t WHERE email='jane@acme.com'"})
        assert memory.get_finished_spans() == (), f"redact={redact}: a database span was exported"


def test_clean_recognized_attrs_are_not_stamped():
    provider, memory = _pipeline()
    _emit(provider, {"gen_ai.output.messages": "the quarterly report is ready"})
    attrs = dict(memory.get_finished_spans()[0].attributes)
    assert attrs["gen_ai.output.messages"] == "the quarterly report is ready"
    assert "aigentrail.redaction.applied" not in attrs


def test_sequence_values_redacted_per_element():
    provider, memory = _pipeline()
    _emit(provider, {"gen_ai.prompt": ["contact jane@acme.com", "then report back"]})
    attrs = dict(memory.get_finished_spans()[0].attributes)
    assert attrs["gen_ai.prompt"] == ("contact [EMAIL]", "then report back")
    assert attrs["aigentrail.redaction.applied"] is True


def test_other_processors_on_the_provider_keep_raw_values():
    app_memory = InMemorySpanExporter()
    provider, gentrail_memory = _pipeline(
        extra_processor=SimpleSpanProcessor(app_memory)
    )
    _emit(provider, {"openinference.span.kind": "LLM", "output.value": "card 4111111111111111 charged"})
    raw = dict(app_memory.get_finished_spans()[0].attributes)
    redacted = dict(gentrail_memory.get_finished_spans()[0].attributes)
    assert raw["output.value"] == "card 4111111111111111 charged"
    assert "aigentrail.redaction.applied" not in raw
    assert redacted["output.value"] == "card [CREDIT_CARD] charged"
    assert redacted["aigentrail.redaction.applied"] is True


def test_redact_disabled_exports_raw():
    provider, memory = _pipeline(redact=False)
    _emit(provider, {"gen_ai.output.messages": "card 4111111111111111"})
    attrs = dict(memory.get_finished_spans()[0].attributes)
    assert attrs["gen_ai.output.messages"] == "card 4111111111111111"


def test_instrument_attaches_to_given_provider():
    provider = TracerProvider()
    with _env(GENTRAIL_API_KEY="k", OTEL_EXPORTER_OTLP_ENDPOINT=UNREACHABLE_COLLECTOR):
        processor = instrument(provider=provider)
    assert isinstance(processor, GentrailSpanProcessor)
    active = getattr(provider, "_active_span_processor")
    assert processor in getattr(active, "_span_processors")


def test_instrument_without_api_key_is_a_noop():
    with _env():
        assert instrument(provider=TracerProvider()) is None


if __name__ == "__main__":
    test_recognized_attrs_leave_pipeline_redacted()
    test_non_genai_spans_never_leave_the_process()
    test_clean_recognized_attrs_are_not_stamped()
    test_sequence_values_redacted_per_element()
    test_other_processors_on_the_provider_keep_raw_values()
    test_redact_disabled_exports_raw()
    test_instrument_attaches_to_given_provider()
    test_instrument_without_api_key_is_a_noop()
    print("ok")
