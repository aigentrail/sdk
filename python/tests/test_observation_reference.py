import importlib
import json
import pathlib
import sys
import types

root = pathlib.Path(__file__).resolve().parents[1]
package = types.ModuleType("gentrail")
package.__path__ = [str(root / "gentrail")]
sys.modules["gentrail"] = package
observation = importlib.import_module("gentrail.observation_reference")
enforcement = importlib.import_module("gentrail.enforcement")


def test_shared_hash_vectors():
    vectors = json.loads((root.parent / "spec/observation_vectors.json").read_text())
    for vector in vectors:
        assert observation.arguments_hash(vector["arguments"]) == vector["sha256"]
    assert observation.arguments_hash("null") == observation.arguments_hash("{}")


def test_receipt_validation_preserves_permission():
    request = {
        "request_id": "request",
        "invocation_id": "invocation",
        "tool_args": {"x": 1},
    }
    reference = dict(
        request_id="request",
        invocation_id="invocation",
        proposal_hash="a" * 64,
        arguments_hash=observation.arguments_hash('{"x":1}'),
    )
    verdict = enforcement._checked_verdict(
        dict(decision="BLOCK", outcome="verified", observation_reference=reference),
        request,
    )
    assert verdict["decision"] == "BLOCK"
    assert verdict["observation_reference"].request_id == "request"
    for field in reference:
        invalid = dict(reference, **{field: "invalid"})
        verdict = enforcement._checked_verdict(
            dict(decision="BLOCK", outcome="verified", observation_reference=invalid),
            request,
        )
        assert verdict["decision"] == "BLOCK"
        assert "observation_reference" not in verdict
    for outcome in [None, {}, [], "unsupported"]:
        verdict = enforcement._checked_verdict(
            dict(decision="GATE", outcome=outcome, observation_reference=reference),
            request,
        )
        assert verdict["decision"] == "GATE"
        assert verdict["outcome"] == "unavailable"
        assert "observation_reference" not in verdict


def test_observation_hashes_actual_arguments():
    original = observation.arguments_hash('{"x":1}')
    reference = observation.DecisionReference(
        "request", "invocation", "a" * 64, original
    )
    attributes = observation.observation_attributes(reference, '{"x":2}')
    assert attributes["aigentrail.decision.arguments_hash"] != original
    assert attributes[
        "aigentrail.decision.arguments_hash"
    ] == observation.arguments_hash('{"x":2}')
    assert attributes["aigentrail.decision.request_id"] == "request"
    assert observation.observation_attributes(None, "invalid") == {}


def test_tracer_hashes_before_redaction_and_truncation():
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import SimpleSpanProcessor
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    module = importlib.import_module("gentrail.otel_exporter")
    assert module._try_import_otel()
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = module.GovernanceTracer(provider.get_tracer("test"), provider)
    parent = tracer.start_invocation("agent", "Agent", "inv", "test")
    original = observation.arguments_hash('{"email":"proposed@example.com"}')
    reference = observation.DecisionReference("request", "inv", "a" * 64, original)
    arguments = json.dumps(dict(email="actual@example.com", padding="x" * 5000))
    tracer.record_tool_call(
        parent,
        agent_id="agent",
        agent_name="Agent",
        name="send",
        args=arguments,
        result="ok",
        duration_ms=1,
        decision_reference=reference,
    )
    span = exporter.get_finished_spans()[0]
    assert span.attributes[
        "aigentrail.decision.arguments_hash"
    ] == observation.arguments_hash(arguments)
    assert span.attributes["aigentrail.decision.arguments_hash"] != original
    assert "actual@example.com" not in span.attributes["input.value"]
    assert len(span.attributes["input.value"]) == 4000
    parent.end()
    provider.shutdown()


if __name__ == "__main__":
    test_shared_hash_vectors()
    test_receipt_validation_preserves_permission()
    test_observation_hashes_actual_arguments()
    test_tracer_hashes_before_redaction_and_truncation()
