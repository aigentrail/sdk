"""Pre-call policy enforcement.

The async evaluator only sees a trace after the tool already ran, so it can
detect but never prevent. Enforcement therefore happens here, in the SDK, at the
before-tool-call hook: ask the backend for a verdict on the proposed tool call
and cancel it on BLOCK before it executes.

Opt-in: a PolicyEnforcer is built only when GENTRAIL_DECIDE_ENDPOINT and
GENTRAIL_API_KEY are both set, so the default behaviour stays observe-only.
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request

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

    def decide(self, tool_name: str, tool_args: dict) -> dict:
        """Return the backend verdict: {"decision": BLOCK|GATE|ALLOW, "rule", "message"}.

        Fails open - a backend error must never break the agent, only forgo
        enforcement for that call.
        """
        body = json.dumps(
            {"event_type": "tool_call", "tool_name": tool_name, "tool_args": tool_args}
        ).encode()
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
                req = urllib.request.Request(
                    poll_url,
                    method="GET",
                    headers={
                        "Authorization": f"Bearer {self.api_key}",
                        "User-Agent": _USER_AGENT,
                    },
                )
                with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                    status = json.loads(resp.read().decode()).get("status", "pending")
            except Exception as e:
                logger.warning("gate poll failed (%s); holding the gate closed", e)
                return "timeout"
            if status != "pending":
                return status
            if time.monotonic() >= deadline:
                return "timeout"
            time.sleep(GATE_POLL_INTERVAL_SECONDS)
