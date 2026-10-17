import asyncio
import copy
import importlib
import json
import pathlib
import os
import socket
import sys
import threading
import time
import types
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[2]
package = types.ModuleType("gentrail")
package.__path__ = [str(ROOT / "python/gentrail")]
sys.modules["gentrail"] = package
enforcement = importlib.import_module("gentrail.enforcement")
admission = importlib.import_module("gentrail.admission")
VECTORS = json.loads((ROOT / "spec/admission_vectors.json").read_text())


@contextmanager
def server(
    vector, *, gate=None, lost=False, redirect=False, slow=False, verdict_override=None
):
    calls = []
    consumes = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
            body = json.loads(raw)
            calls.append((self.path, body))
            assert self.headers["Authorization"] == "Bearer key"
            if self.path == "/api/v1/decide":
                response = {
                    "decision": "GATE" if gate else "ALLOW",
                    "outcome": "verified",
                    "admission": vector["link"],
                }
                if verdict_override is not None:
                    response = verdict_override
                if gate:
                    response["approval"] = {"status_url": "/approval"}
            elif self.path == "/reserve":
                assert body == {"proposal_hash": vector["link"]["proposal_hash"]}
                response = vector["reserved"]
            elif self.path == "/consume":
                consumes.append(body)
                assert body == {"proposal_hash": vector["link"]["proposal_hash"]}
                if lost:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    return
                response = copy.deepcopy(vector["consumed"])
                if len(consumes) > 1:
                    response["execution_authorized"] = False
            else:
                raise AssertionError(self.path)
            if redirect and self.path == "/reserve":
                self.send_response(307)
                self.send_header("Location", "/unexpected")
                self.end_headers()
                return
            self.reply(response)

        def do_GET(self):
            calls.append((self.path, None))
            self.reply({"status": gate})

        def reply(self, response):
            self.send_response(200)
            self.end_headers()
            if slow and self.path != "/api/v1/decide":
                time.sleep(0.3)
            try:
                self.wfile.write(json.dumps(response).encode())
            except BrokenPipeError:
                pass

        def log_message(self, *args):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.01})
    thread.start()
    try:
        yield f"http://127.0.0.1:{srv.server_port}", calls, consumes
    finally:
        srv.shutdown()
        srv.server_close()
        thread.join()


def enforcer(endpoint, **options):
    return enforcement.PolicyEnforcer(
        endpoint,
        "key",
        strict_admission=True,
        clock=lambda: 100,
        id_gen=lambda: "call",
        **options,
    )


def test_shared_admission_vectors_sync_and_async():
    for vector in VECTORS:
        for asynchronous in (False, True):
            with server(vector) as (endpoint, calls, consumes):
                sync = enforcer(endpoint)
                if asynchronous:
                    client = enforcement.AsyncPolicyEnforcer.from_sync(sync)
                    allowed, message = asyncio.run(
                        enforcement.enforce_async(client, "Read", {})
                    )
                else:
                    allowed, message = enforcement.enforce(sync, "Read", {})
                assert allowed == vector["allowed"], (vector["name"], asynchronous)
                if vector["name"] == "quota exhausted":
                    assert (
                        message
                        == "This agent has used its tool-call allowance for the current quota window."
                    )
                assert calls[0][1]["admission_protocol"] == "quota_v1"
                assert len(consumes) <= 1


def test_gate_precedes_reservation_and_denial_never_consumes():
    for status in ("approved", "denied", "expired"):
        for asynchronous in (False, True):
            with server(VECTORS[0], gate=status) as (endpoint, calls, consumes):
                sync = enforcer(endpoint)
                if asynchronous:
                    result = asyncio.run(
                        enforcement.enforce_async(
                            enforcement.AsyncPolicyEnforcer.from_sync(sync), "Read", {}
                        )
                    )
                else:
                    result = enforcement.enforce(sync, "Read", {})
                assert result[0] == (status == "approved")
                expected = ["/api/v1/decide", "/approval"]
                if status == "approved":
                    expected += ["/reserve", "/consume"]
                assert [path for path, _ in calls] == expected


def test_decide_does_not_consume_and_replay_cannot_run_twice():
    with server(VECTORS[0]) as (endpoint, calls, consumes):
        client = enforcer(endpoint)
        assert client.decide("Read", {})["decision"] == "ALLOW"
        assert not consumes
        assert enforcement.enforce(client, "Read", {})[0]
        assert not enforcement.enforce(client, "Read", {})[0]
        assert len(consumes) == 2


def test_lost_reply_and_redirect_never_retry_or_authorize():
    for options in ({"lost": True}, {"redirect": True}):
        with server(VECTORS[0], **options) as (endpoint, calls, consumes):
            assert not enforcement.enforce(enforcer(endpoint), "Read", {})[0]
            assert len(consumes) == (1 if options.get("lost") else 0)
            assert all(path != "/unexpected" for path, _ in calls)


def test_strict_outage_and_malformed_resources_fail_closed():
    assert not enforcement.enforce(enforcer("http://127.0.0.1:1"), "Read", {})[0]
    for link in (None, False, {}, {"required": True}):
        vector = {**VECTORS[0], "link": link}
        with server(vector) as (endpoint, calls, consumes):
            assert not enforcement.enforce(enforcer(endpoint), "Read", {})[0]
            assert len(calls) == 1
    with server(VECTORS[0]) as (endpoint, calls, consumes):
        ordinary = enforcement.PolicyEnforcer(endpoint, "key")
        assert not enforcement.enforce(ordinary, "Read", {})[0]
        assert "admission_protocol" not in calls[0][1]
        assert not consumes


def test_deadline_and_response_size_are_bounded():
    with server(VECTORS[0]) as (endpoint, calls, consumes):
        ticks = iter([0, 0, 10])
        client = enforcer(endpoint, monotonic=lambda: next(ticks))
        assert not enforcement.enforce(client, "Read", {})[0]
        assert not consumes
    vector = copy.deepcopy(VECTORS[0])
    vector["reserved"]["padding"] = "x" * 65536
    with server(vector) as (endpoint, calls, consumes):
        assert not enforcement.enforce(enforcer(endpoint), "Read", {})[0]
        assert not consumes


def test_slow_receipt_is_interrupted_at_total_deadline():
    previous = admission.DEADLINE_SECONDS
    admission.DEADLINE_SECONDS = 0.08
    try:
        with server(VECTORS[0], slow=True) as (endpoint, calls, consumes):
            started = time.monotonic()
            assert not enforcement.enforce(enforcer(endpoint), "Read", {})[0]
            assert time.monotonic() - started < 0.25
            assert not consumes
    finally:
        admission.DEADLINE_SECONDS = previous


def test_strict_decision_metadata_and_no_quota_behavior():
    for verdict in (
        {},
        {"decision": "ALLOW"},
        {"decision": "ALLOW", "outcome": "unknown"},
        {"decision": "ALLOW", "outcome": "request_conflict"},
        {"decision": "SHADOW", "outcome": "verified"},
    ):
        with server(VECTORS[0], verdict_override=verdict) as (
            endpoint,
            calls,
            consumes,
        ):
            assert not enforcement.enforce(enforcer(endpoint), "Read", {})[0]
            assert len(calls) == 1
    with server(
        VECTORS[0], verdict_override={"decision": "ALLOW", "outcome": "verified"}
    ) as (endpoint, calls, consumes):
        assert enforcement.enforce(enforcer(endpoint), "Read", {})[0]
        assert len(calls) == 1


def test_strict_environment_setup_cannot_silently_disable_enforcement():
    names = ("GENTRAIL_DECIDE_ENDPOINT", "GENTRAIL_API_KEY")
    saved = {name: os.environ.pop(name, None) for name in names}
    try:
        for client in (enforcement.PolicyEnforcer, enforcement.AsyncPolicyEnforcer):
            assert client.from_env() is None
            try:
                client.from_env(strict_admission=True)
            except ValueError:
                pass
            else:
                raise AssertionError("strict setup silently disabled enforcement")
    finally:
        for name, value in saved.items():
            if value is not None:
                os.environ[name] = value


if __name__ == "__main__":
    for name, test in list(globals().items()):
        if name.startswith("test_"):
            test()
            print(name, "PASS")
