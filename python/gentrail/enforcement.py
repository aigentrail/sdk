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
from typing import Any, Callable

from .admission import (
    AdmissionClient,
    NoRedirect,
    PROTOCOL,
    QuotaExhaustedError,
    same_origin_link,
)

from .observation_reference import DECISION_OUTCOMES, checked_reference

logger = logging.getLogger(__name__)

GATE_POLL_INTERVAL_SECONDS = 2.0

# Identify the client on every request. urllib's default "Python-urllib/x.y"
# reads as a bot to edge WAFs (e.g. Cloudflare fronting the backend answers 403),
# which would silently fail-open enforcement; a named agent is allowed through.
_USER_AGENT = "gentrail-sdk-python"


class PolicyEnforcer:
    """Synchronous client for the backend's /api/v1/decide endpoint."""

    def __init__(
        self,
        endpoint: str,
        api_key: str,
        timeout: float = 3.0,
        *,
        strict_admission: bool = False,
        clock: Callable[[], float] = time.time,
        monotonic: Callable[[], float] = time.monotonic,
        id_gen: Callable[[], str] = lambda: uuid.uuid4().hex,
    ) -> None:
        self.base = endpoint.rstrip("/")
        self.url = self.base + "/api/v1/decide"
        self.api_key = api_key
        self.timeout = timeout
        self.strict_admission = strict_admission
        self._id_gen = id_gen
        self._opener = urllib.request.build_opener(NoRedirect())
        self._admission = AdmissionClient(
            self.url, api_key, timeout, clock=clock, monotonic=monotonic
        )
        # A GATE hold blocks the tool while a human decides. Bound the wait so an
        # unanswered gate never hangs the agent forever; on timeout the gate
        # fails closed (the tool stays cancelled). The backend hold expires
        # independently (deny-by-default) at its own expires_at.
        self.gate_timeout = float(
            os.environ.get("GENTRAIL_GATE_TIMEOUT_SECONDS", "120")
        )

    @classmethod
    def from_env(cls, *, strict_admission: bool = False) -> "PolicyEnforcer | None":
        endpoint = os.environ.get("GENTRAIL_DECIDE_ENDPOINT", "").strip()
        api_key = os.environ.get("GENTRAIL_API_KEY", "").strip()
        if not endpoint or not api_key:
            if strict_admission:
                raise ValueError(
                    "Strict admission needs a decide endpoint and agent-bound API key"
                )
            return None
        return cls(endpoint, api_key, strict_admission=strict_admission)

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

        Decision errors fail open by default. Strict admission fails closed;
        callers must use enforce to obtain quota execution authority.
        """
        payload = {
            "event_type": "tool_call",
            "tool_name": tool_name,
            "tool_args": tool_args,
            "request_id": request_id or self._id_gen(),
        }
        if self.strict_admission:
            payload["admission_protocol"] = PROTOCOL
        if agent_id:
            payload["agent_id"] = agent_id
        invocation_id = invocation_id or ambient_otel_trace_id()
        if invocation_id:
            payload["invocation_id"] = invocation_id
        try:
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
            with self._opener.open(req, timeout=self.timeout) as resp:
                response = resp.read(2 * 1024 * 1024 + 1)
                if len(response) > 2 * 1024 * 1024:
                    raise ValueError("decide response exceeds size limit")
                verdict = json.loads(response.decode())
                verdict = _checked_verdict(verdict, payload)
                verdict["_request_id"] = payload["request_id"]
                if self.strict_admission and verdict["outcome"] != "verified":
                    verdict["decision"] = "BLOCK"
                return verdict
        except Exception as e:
            logger.warning("enforcement decide failed (%s) for tool %s", e, tool_name)
            return {
                "decision": "BLOCK" if self.strict_admission else "ALLOW",
                "outcome": "unavailable",
            }

    def authorize_admission(self, verdict: dict) -> tuple[bool, str]:
        if "admission" not in verdict:
            return True, ""
        if not self.strict_admission:
            return (
                False,
                "Strict tool-call quotas require strict_admission and an agent-bound credential.",
            )
        try:
            self._admission.authorize(
                verdict.get("_request_id", ""), verdict["admission"]
            )
        except QuotaExhaustedError:
            return (
                False,
                "This agent has used its tool-call allowance for the current quota window.",
            )
        except Exception as error:
            logger.warning("tool-call admission failed (%s)", error)
            return (
                False,
                "Gentrail could not authorize this tool-call attempt; the call was not run.",
            )
        return True, ""

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
        try:
            poll_url = same_origin_link(self.url, status_url)
        except ValueError:
            return "timeout"
        deadline = time.monotonic() + (
            self.gate_timeout if timeout is None else timeout
        )
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
        with self._opener.open(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode()).get("status", "pending")


class AsyncPolicyEnforcer:
    """Async twin of PolicyEnforcer for asyncio-native callers.

    Each HTTP round trip is the sync urllib call moved off the event loop with
    asyncio.to_thread, so the base install still needs no HTTP client
    dependency, while GATE polling waits with asyncio.sleep instead of
    parking a thread. Strict admission and approval behavior match the sync client.
    """

    def __init__(
        self, endpoint: str, api_key: str, timeout: float = 3.0, **options: Any
    ) -> None:
        self._sync = PolicyEnforcer(endpoint, api_key, timeout, **options)

    @classmethod
    def from_sync(cls, enforcer: PolicyEnforcer) -> "AsyncPolicyEnforcer":
        instance = cls.__new__(cls)
        instance._sync = enforcer
        return instance

    async def authorize_admission(self, verdict: dict) -> tuple[bool, str]:
        return await asyncio.to_thread(self._sync.authorize_admission, verdict)

    @classmethod
    def from_env(
        cls, *, strict_admission: bool = False
    ) -> "AsyncPolicyEnforcer | None":
        sync = PolicyEnforcer.from_env(strict_admission=strict_admission)
        if sync is None:
            return None
        return cls.from_sync(sync)

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
        try:
            poll_url = same_origin_link(self._sync.url, status_url)
        except ValueError:
            return "timeout"
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
    return finish_enforcement(enforcer, verdict)


def finish_enforcement(enforcer, verdict: dict) -> tuple[bool, str]:
    decision = verdict.get("decision")
    if decision == "BLOCK":
        return False, _verdict_message(verdict)
    if decision == "GATE":
        status = enforcer.await_gate(verdict.get("approval") or {})
        if status != "approved":
            return False, f"{_verdict_message(verdict)} (approval {status})"
    if "admission" in verdict:
        return enforcer.authorize_admission(verdict)
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
        if status != "approved":
            return False, f"{_verdict_message(verdict)} (approval {status})"
    if "admission" in verdict:
        return await enforcer.authorize_admission(verdict)
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


def _checked_verdict(verdict: Any, request: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(verdict, dict):
        raise ValueError("decide verdict must be a JSON object")
    outcome = verdict.get("outcome")
    if not isinstance(outcome, str) or outcome not in DECISION_OUTCOMES:
        outcome = "unavailable"
    if verdict.get("decision") not in ("ALLOW", "BLOCK", "GATE"):
        outcome = "unavailable"
    verdict["outcome"] = outcome
    reference = None
    if outcome == "verified":
        reference = checked_reference(verdict.get("observation_reference"), request)
    if reference is None:
        verdict.pop("observation_reference", None)
    else:
        verdict["observation_reference"] = reference
    return verdict
