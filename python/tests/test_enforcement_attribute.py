"""The tool span carries the pre-execution verdict (GEN-238).

A call the decide endpoint blocked or gated still records a tool span; that
span must carry aigentrail.enforcement.decision so ingestion copies it onto the
tool_call item and the evaluator stamps the violation outcome=prevented.
Runs against the real OTel SDK with an in-memory exporter (a project dep, no
strands needed). Runnable as `python tests/test_enforcement_attribute.py` or
via pytest.
"""

import importlib.util
import os

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "otel_exporter", os.path.join(_HERE, "..", "gentrail", "otel_exporter.py")
)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)
GovernanceTracer = _mod.GovernanceTracer
assert _mod._try_import_otel(), "OTel packages must be installed for this test"


def _tracer_with_memory_exporter():
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return GovernanceTracer(provider.get_tracer("test"), provider, redact=False), exporter


def _record(gt, exporter, **kwargs):
    parent = gt.start_invocation("ag1", "agent", "j1", "hi")
    gt.record_tool_call(
        parent,
        agent_id="ag1",
        agent_name="agent",
        name=kwargs.pop("name", "run_sql"),
        args="{}",
        result="blocked",
        duration_ms=1.0,
        **kwargs,
    )
    parent.end()
    spans = {s.name: s for s in exporter.get_finished_spans()}
    exporter.clear()
    return spans


def test_blocked_tool_span_carries_enforcement_decision():
    gt, exporter = _tracer_with_memory_exporter()
    spans = _record(gt, exporter, enforced_decision="BLOCK")
    attrs = dict(spans["run_sql"].attributes)
    assert attrs["aigentrail.enforcement.decision"] == "BLOCK"
    assert attrs["openinference.span.kind"] == "TOOL"


def test_unenforced_tool_span_has_no_decision_attribute():
    gt, exporter = _tracer_with_memory_exporter()
    spans = _record(gt, exporter)
    assert "aigentrail.enforcement.decision" not in dict(spans["run_sql"].attributes)


if __name__ == "__main__":
    test_blocked_tool_span_carries_enforcement_decision()
    test_unenforced_tool_span_has_no_decision_attribute()
    print("ok")
