"""Pre-call policy enforcement.

The async evaluator only sees a trace after the tool already ran, so it can
detect but never prevent. Enforcement therefore happens here, in the SDK, at the
before-tool-call hook: ask the backend for a verdict on the proposed tool call
and cancel it on BLOCK before it executes.

Opt-in: a PolicyEnforcer is built only when GENTRAIL_DECIDE_ENDPOINT and
GENTRAIL_API_KEY are both set, so the default behaviour stays observe-only.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import urllib.request
import uuid

logger = logging.getLogger(__name__)

GATE_POLL_INTERVAL_SECONDS = 2.0

# Identify the client on every request. urllib's default "Python-urllib/x.y"
# reads as a bot to edge WAFs (e.g. Cloudflare fronting the backend answers 403),
# which would silently fail-open enforcement; a named agent is allowed through.
_USER_AGENT = "gentrail-sdk-python"


class PolicyEnforcer:
    """Synchronous client for the backend's /api/v1/decide endpoint."""

    def __init__(self, endpoint: str, api_key: str, timeout: float = 3.0):
        self.base = endpoint.rstrip("/")
        self.url = self.base + "/api/v1/decide"
        self.api_key = api_key
        self.timeout = timeout
        # A GATE hold blocks the tool while a human decides. Bound the wait so an
        # unanswered gate never hangs the agent forever; on timeout the gate
        # fails closed (the tool stays cancelled). The backend hold expires
        # independently (deny-by-default) at its own expires_at.
        self.gate_timeout = float(
            os.environ.get("GENTRAIL_GATE_TIMEOUT_SECONDS", "120")
        )

    @classmethod
    def from_env(cls) -> "PolicyEnforcer | None":
        endpoint = os.environ.get("GENTRAIL_DECIDE_ENDPOINT", "").strip()
        api_key = os.environ.get("GENTRAIL_API_KEY", "").strip()
        if not endpoint or not api_key:
            return None
        return cls(endpoint, api_key)

    def decide(
        self,
        tool_name: str,
        tool_args: dict,
        *,
        agent_id: str = "",
        invocation_id: str = "",
        request_id: str = "",
    ) -> dict:
        """Return the backend verdict: {"decision": BLOCK|GATE|ALLOW, "rule", "message"}.

        agent_id scopes agent-targeted and windowed rules to the caller;
        invocation_id (the invocation's OTel trace id) lets the backend join
        the enforcement record to the ingested trace and gives a GATE approver
        context, and defaults to the ambient trace when a span is recording;
        request_id makes the backend's GATE/BLOCK writes idempotent under
        retries. The backend requires a request_id, so a caller without a
        framework call id gets a synthesized one (unique, so it never dedups a
        legitimate second call). It refuses to record a BLOCK/GATE with no
        agent_id or invocation_id, since it could not be joined to its trace
        and would double-count against the evaluator's own row.

        Fails open - a backend error must never break the agent, only forgo
        enforcement for that call.
        """
        payload = {
            "event_type": "tool_call",
            "tool_name": tool_name,
            "tool_args": tool_args,
            "request_id": request_id or uuid.uuid4().hex,
        }
        if agent_id:
            payload["agent_id"] = agent_id
        invocation_id = invocation_id or ambient_otel_trace_id()
        if invocation_id:
            payload["invocation_id"] = invocation_id
        body = json.dumps(payload).encode()
        req = urllib.request.Request(
            self.url,
            data=body,
            method="POST",
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": _USER_AGENT,
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.warning("enforcement decide failed (%s); allowing tool %s", e, tool_name)
            return {"decision": "ALLOW"}

    def await_gate(self, approval: dict, *, timeout: float | None = None) -> str:
        """Poll a GATE hold's status resource until it resolves, returning the
        final status: "approved", "denied", "expired", or "timeout".

        Unlike decide(), this fails CLOSED: an unresolved or unreachable hold
        returns a non-approved status so the caller keeps the tool cancelled.
        Running a gated action without a confirmed approval is exactly what the
        gate exists to prevent.
        """
        status_url = (approval or {}).get("status_url")
        if not status_url:
            return "timeout"
        poll_url = self.base + status_url
        deadline = time.monotonic() + (self.gate_timeout if timeout is None else timeout)
        while True:
            try:
                status = self._poll_gate_once(poll_url)
            except Exception as e:
                logger.warning("gate poll failed (%s); holding the gate closed", e)
                return "timeout"
            if status != "pending":
                return status
            if time.monotonic() >= deadline:
                return "timeout"
            time.sleep(GATE_POLL_INTERVAL_SECONDS)

    def _poll_gate_once(self, poll_url: str) -> str:
        req = urllib.request.Request(
            poll_url,
            method="GET",
            headers={
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": _USER_AGENT,
            },
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode()).get("status", "pending")


class AsyncPolicyEnforcer:
    """Async twin of PolicyEnforcer for asyncio-native callers.

    Each HTTP round trip is the sync urllib call moved off the event loop with
    asyncio.to_thread, so the base install still needs no HTTP client
    dependency, while GATE polling waits with asyncio.sleep instead of
    parking a thread. Semantics match the sync client exactly: decide fails
    open, await_gate fails closed, same environment configuration.
    """

    def __init__(self, endpoint: str, api_key: str, timeout: float = 3.0):
        self._sync = PolicyEnforcer(endpoint, api_key, timeout)

    @classmethod
    def from_env(cls) -> "AsyncPolicyEnforcer | None":
        sync = PolicyEnforcer.from_env()
        if sync is None:
            return None
        return cls(sync.base, sync.api_key, sync.timeout)

    @property
    def base(self) -> str:
        return self._sync.base

    @property
    def api_key(self) -> str:
        return self._sync.api_key

    @property
    def timeout(self) -> float:
        return self._sync.timeout

    @property
    def gate_timeout(self) -> float:
        return self._sync.gate_timeout

    async def decide(
        self,
        tool_name: str,
        tool_args: dict,
        *,
        agent_id: str = "",
        invocation_id: str = "",
        request_id: str = "",
    ) -> dict:
        return await asyncio.to_thread(
            self._sync.decide,
            tool_name,
            tool_args,
            agent_id=agent_id,
            invocation_id=invocation_id,
            request_id=request_id,
        )

    async def await_gate(self, approval: dict, *, timeout: float | None = None) -> str:
        status_url = (approval or {}).get("status_url")
        if not status_url:
            return "timeout"
        poll_url = self._sync.base + status_url
        deadline = time.monotonic() + (
            self._sync.gate_timeout if timeout is None else timeout
        )
        while True:
            try:
                status = await asyncio.to_thread(self._sync._poll_gate_once, poll_url)
            except Exception as e:
                logger.warning("gate poll failed (%s); holding the gate closed", e)
                return "timeout"
            if status != "pending":
                return status
            if time.monotonic() >= deadline:
                return "timeout"
            await asyncio.sleep(GATE_POLL_INTERVAL_SECONDS)


def _verdict_message(verdict: dict) -> str:
    decision = verdict.get("decision", "")
    rule = verdict.get("rule", "")
    return verdict.get("message") or f"{decision} by policy {rule}".strip()


def enforce(
    enforcer,
    tool_name: str,
    tool_args: dict,
    *,
    agent_id: str = "",
    invocation_id: str = "",
    request_id: str = "",
) -> "tuple[bool, str]":
    """One decide-and-gate cycle: (allowed, cancel_message).

    ALLOW and an approved GATE return (True, ""); BLOCK and a denied, expired,
    or unanswered GATE return (False, message) where the message is what the
    model should see in place of the tool result. This is the framework-neutral
    core the adapters share; enforcer is any object with the PolicyEnforcer
    decide/await_gate surface.
    """
    verdict = enforcer.decide(
        tool_name,
        tool_args,
        agent_id=agent_id,
        invocation_id=invocation_id,
        request_id=request_id,
    )
    decision = verdict.get("decision")
    if decision == "BLOCK":
        return False, _verdict_message(verdict)
    if decision == "GATE":
        status = enforcer.await_gate(verdict.get("approval") or {})
        if status == "approved":
            return True, ""
        return False, f"{_verdict_message(verdict)} (approval {status})"
    return True, ""


async def enforce_async(
    enforcer,
    tool_name: str,
    tool_args: dict,
    *,
    agent_id: str = "",
    invocation_id: str = "",
    request_id: str = "",
) -> "tuple[bool, str]":
    """enforce() for an AsyncPolicyEnforcer-shaped enforcer."""
    verdict = await enforcer.decide(
        tool_name,
        tool_args,
        agent_id=agent_id,
        invocation_id=invocation_id,
        request_id=request_id,
    )
    decision = verdict.get("decision")
    if decision == "BLOCK":
        return False, _verdict_message(verdict)
    if decision == "GATE":
        status = await enforcer.await_gate(verdict.get("approval") or {})
        if status == "approved":
            return True, ""
        return False, f"{_verdict_message(verdict)} (approval {status})"
    return True, ""


def ambient_otel_trace_id() -> str:
    """The current OpenTelemetry trace id as 32-char hex, "" when there is no
    recording span or no opentelemetry install.

    Sent as invocation_id so the backend can join the enforcement record to the
    trace an OTel-instrumented framework run is already exporting.
    """
    try:
        from opentelemetry import trace

        ctx = trace.get_current_span().get_span_context()
        if not ctx.is_valid:
            return ""
        return format(ctx.trace_id, "032x")
    except Exception:
        return ""
