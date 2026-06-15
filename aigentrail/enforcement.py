"""Pre-call policy enforcement.

The async evaluator only sees a trace after the tool already ran, so it can
detect but never prevent. Enforcement therefore happens here, in the SDK, at the
before-tool-call hook: ask the backend for a verdict on the proposed tool call
and cancel it on BLOCK before it executes.

Opt-in: a PolicyEnforcer is built only when AIGENTRAIL_DECIDE_ENDPOINT and
AIGENTRAIL_API_KEY are both set, so the default behaviour stays observe-only.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request

logger = logging.getLogger(__name__)


class PolicyEnforcer:
    """Synchronous client for the backend's /api/v1/decide endpoint."""

    def __init__(self, endpoint: str, api_key: str, timeout: float = 3.0):
        self.url = endpoint.rstrip("/") + "/api/v1/decide"
        self.api_key = api_key
        self.timeout = timeout

    @classmethod
    def from_env(cls) -> "PolicyEnforcer | None":
        endpoint = os.environ.get("AIGENTRAIL_DECIDE_ENDPOINT", "").strip()
        api_key = os.environ.get("AIGENTRAIL_API_KEY", "").strip()
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
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return json.loads(resp.read().decode())
        except Exception as e:
            logger.warning("enforcement decide failed (%s); allowing tool %s", e, tool_name)
            return {"decision": "ALLOW"}
