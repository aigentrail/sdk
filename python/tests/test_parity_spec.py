"""Checks the Python SDK against the specs shared by every Gentrail SDK in
../../spec: journal seal vectors, enforcement outcomes, and span attributes.
Runnable as `python tests/test_parity_spec.py` or via pytest."""

import json
import os
import sys
import threading
import types
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter

_HERE = os.path.dirname(os.path.abspath(__file__))
_SPEC_DIR = os.path.join(_HERE, "..", "..", "spec")
_PKG_DIR = os.path.abspath(os.path.join(_HERE, "..", "gentrail"))
if "gentrail" not in sys.modules:
    _pkg = types.ModuleType("gentrail")
    _pkg.__path__ = [_PKG_DIR]
    sys.modules["gentrail"] = _pkg

from gentrail import enforcement as _enforcement  # noqa: E402
from gentrail import export_filter as _export_filter  # noqa: E402
from gentrail import otel_exporter as _otel  # noqa: E402
from gentrail.canonical_json import canonical_json  # noqa: E402
from gentrail.evidence_ledger import (  # noqa: E402
    DecisionJournal,
    EvidenceLedger,
    ModelCallRecord,
    ToolCallRecord,
    journal_canonical_document,
)

assert _otel._try_import_otel(), "OTel packages must be installed for this test"


def _spec(name):
    with open(os.path.join(_SPEC_DIR, name), encoding="utf-8") as f:
        return json.load(f)


def _utc(timestamp):
    return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))


def _journal_from_document(document):
    return DecisionJournal(
        journal_id=document["journal_id"],
        agent_id=document["agent_id"],
        agent_name=document["agent_name"],
        started_at=_utc(document["started_at"]),
        user_message=document["user_message"],
        final_response=document["final_response"],
        model_calls=[
            ModelCallRecord(
                model_id=call["model_id"],
                prompt_preview=call["prompt_preview"],
                cot_reasoning=call["cot_reasoning"],
                token_usage=call["token_usage"],
                latency_ms=call["latency_ms"],
            )
            for call in document["model_calls"]
        ],
        tool_calls=[
            ToolCallRecord(
                tool_name=call["tool_name"],
                tool_args=call["tool_args"],
                result=call["result"],
                duration_ms=call["duration_ms"],
            )
            for call in document["tool_calls"]
        ],
        total_tokens=document["total_tokens"],
    )


def test_journal_seal_matches_shared_vectors():
    vectors = _spec("journal_vectors.json")
    assert vectors, "no journal vectors"
    for vector in vectors:
        journal = _journal_from_document(vector["journal"])
        integrity_hash = journal.seal(now=_utc(vector["journal"]["completed_at"]))
        canonical = canonical_json(journal_canonical_document(journal))
        assert canonical == vector["canonical"], f"{vector['name']}: canonical JSON differs"
        assert integrity_hash == vector["integrity_hash"], f"{vector['name']}: hash differs"


def test_ledger_create_seal_and_lookup():
    ledger = EvidenceLedger()
    journal = ledger.create("agent-1", "Agent One")
    assert ledger.get(journal.journal_id) is journal
    assert ledger.get_by_agent("agent-1") == [journal]
    integrity_hash = ledger.seal(journal.journal_id)
    assert journal.sealed and journal.integrity_hash == integrity_hash and len(integrity_hash) == 64
    assert ledger.seal("missing") is None


def test_canonical_json_numbers_follow_ecmascript():
    cases = {1.5e-7: "1.5e-7", 1e21: "1e+21", 1e20: "100000000000000000000", 0.0001: "0.0001", -0.5: "-0.5", 2.0: "2"}
    for number, want in cases.items():
        assert canonical_json(number) == want, f"{number!r} -> {canonical_json(number)!r}, want {want!r}"


class _DecideServer:
    def __init__(self):
        self.verdict = {}
        self.gate_status = "pending"
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _reply(self, body):
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_POST(self):
                self.rfile.read(int(self.headers.get("Content-Length", "0")))
                self._reply(server.verdict)

            def do_GET(self):
                self._reply({"status": server.gate_status})

        self._http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.endpoint = f"http://127.0.0.1:{self._http.server_address[1]}"
        threading.Thread(target=self._http.serve_forever, daemon=True).start()

    def close(self):
        self._http.shutdown()


def test_enforce_matches_shared_vectors():
    server = _DecideServer()
    try:
        enforcer = _enforcement.PolicyEnforcer(server.endpoint, "key")
        enforcer.gate_timeout = 1.0
        for vector in _spec("enforce_vectors.json"):
            server.verdict = vector["verdict"]
            server.gate_status = vector["gate_status"] or "pending"
            allowed, message = _enforcement.enforce(enforcer, "wire_transfer", {"amount": 5}, agent_id="a")
            assert (allowed, message) == (vector["allowed"], vector["message"]), f"{vector['name']}: {(allowed, message)}"
    finally:
        server.close()


def _tracer_with_memory_exporter(redact=True):
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    return _otel.GovernanceTracer(provider.get_tracer("test"), provider, redact=redact), exporter


def test_spans_match_shared_spec():
    spec = _spec("spans.json")
    tracer, exporter = _tracer_with_memory_exporter()
    limit = spec["value_rune_limit"]
    parent = tracer.start_invocation("agent-1", "Agent", "journal-1", "x" * (limit + 10))
    tracer.record_model_call(parent, model_id="m", prompt="p", response_text="r", input_tokens=1, output_tokens=2, latency_ms=3.0)
    tracer.record_tool_call(parent, agent_id="agent-1", agent_name="Agent", name="lookup", args="{}", result="ok", duration_ms=4.0, enforced_decision="BLOCK")
    tracer.end_invocation(parent, response="done", total_tokens=3, tool_count=1, integrity_hash="h")
    spans = {span.name: span for span in exporter.get_finished_spans()}

    invocation = dict(spans[spec["invocation"]["name"]].attributes)
    for key in spec["invocation"]["start_attributes"] + spec["invocation"]["end_attributes"]:
        assert key in invocation, f"invocation span missing {key}"
    assert invocation["openinference.span.kind"] == spec["invocation"]["span_kind"]
    assert invocation["source"] == spec["source"]
    assert len(invocation["input.value"]) == limit

    model_call = dict(spans[spec["model_call"]["name"]].attributes)
    for key in spec["model_call"]["attributes"]:
        assert key in model_call, f"model_call span missing {key}"
    assert model_call["openinference.span.kind"] == spec["model_call"]["span_kind"]

    tool_call = dict(spans["lookup"].attributes)
    for key in spec["tool_call"]["attributes"]:
        assert key in tool_call, f"tool_call span missing {key}"
    assert tool_call["openinference.span.kind"] == spec["tool_call"]["span_kind"]
    assert tool_call[spec["enforcement_decision_attribute"]] == "BLOCK"


def test_httpx_transport_records_model_calls():
    import httpx

    tracer, exporter = _tracer_with_memory_exporter(redact=False)
    statuses = iter([200, 503])
    base = httpx.MockTransport(lambda request: httpx.Response(next(statuses)))
    with httpx.Client(transport=tracer.httpx_transport(base)) as client:
        client.post("https://api.example.com/v1/chat")
        client.get("https://api.example.com/v1/models")
    model_calls = [dict(s.attributes) for s in exporter.get_finished_spans() if s.name == "governance.model_call"]
    invocations = [dict(s.attributes) for s in exporter.get_finished_spans() if s.name == "governance.invocation"]
    assert [call["llm.model_name"] for call in model_calls] == ["api.example.com", "api.example.com"]
    assert [call["input.value"] for call in model_calls] == ["POST /v1/chat", "GET /v1/models"]
    assert [inv["aigentrail.invocation.status"] for inv in invocations] == ["ok", "http_503"]


def test_export_filter_lists_match_spec():
    spec = _spec("spans.json")["export_filter"]
    assert list(_export_filter.GENAI_SIGNAL_ATTRIBUTE_PREFIXES) == spec["attribute_prefixes"]
    assert sorted(_export_filter.GENAI_SIGNAL_ATTRIBUTE_KEYS) == sorted(spec["attribute_keys"])


def test_export_filter_matches_shared_vectors():
    for vector in _spec("export_filter_vectors.json"):
        got = _export_filter.carries_genai_signal(vector["attributes"].keys())
        assert got == vector["exported"], f"{vector['name']}: exported={got}"


if __name__ == "__main__":
    for _name, _fn in sorted(globals().items()):
        if _name.startswith("test_") and callable(_fn):
            _fn()
            print(f"ok  {_name}")
    print("PARITY SPEC TESTS PASSED")
