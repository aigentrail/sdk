"""Gentrail enforcement for the OpenAI Agents SDK.

enforcement_guardrail() builds a tool input guardrail that asks the Gentrail
decide endpoint before a function tool runs. Attach it to the tools that need
governance:

    from agents import function_tool
    from gentrail.openai_agents import enforcement_guardrail

    @function_tool(tool_input_guardrails=[enforcement_guardrail()])
    def run_sql(database: str, sql: str) -> str: ...

BLOCK maps to ToolGuardrailFunctionOutput.reject_content: the tool never
executes and the model sees the policy message as the tool output.

GATE mapping: the framework's needs_approval interruption flow hands the
approve/reject decision to the calling application through RunState, which is
built for approvals the application itself answers. A Gentrail gate is decided
in the Gentrail dashboard against a durable approval hold, so the guardrail
awaits that hold inline instead (asyncio polling of its status URL): approval
lets the tool run, and a denied, expired, or unanswered hold rejects the call
with the policy message. The run loop needs no interruption handling, and
BLOCK and GATE ride the same guardrail seam.

The guardrail sends the enforcement identity fields the backend joins on:
agent_id from the owning agent's name, request_id from the framework's
tool_call_id, and invocation_id from the ambient OpenTelemetry trace when the
process is OTel-instrumented.

Importing this module never imports the agents package; the factory does, so
only callers that build the guardrail need the openai-agents install.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from .enforcement import (
    AsyncPolicyEnforcer,
    PolicyEnforcer,
    ambient_otel_trace_id,
    enforce_async,
)

if TYPE_CHECKING:
    from agents.tool_guardrails import ToolInputGuardrail

_UNCONFIGURED = (
    "gentrail enforcement is not configured: "
    "set GENTRAIL_DECIDE_ENDPOINT and GENTRAIL_API_KEY"
)


def _call_facts(data: Any) -> "tuple[str, dict, str, str]":
    """(tool_name, tool_args, tool_call_id, agent_name) from guardrail data."""
    ctx = data.context
    raw = getattr(ctx, "tool_arguments", "") or "{}"
    try:
        parsed = json.loads(raw)
    except ValueError:
        parsed = None
    tool_args = parsed if isinstance(parsed, dict) else {"raw": raw}
    agent_name = getattr(getattr(data, "agent", None), "name", "") or ""
    return ctx.tool_name, tool_args, getattr(ctx, "tool_call_id", "") or "", agent_name


def _as_async(enforcer: Any) -> Any:
    """Any other object is trusted to already speak the async decide/await_gate
    surface, which is what lets tests drive the guardrail with a fake."""
    if isinstance(enforcer, PolicyEnforcer):
        return AsyncPolicyEnforcer(enforcer.base, enforcer.api_key, enforcer.timeout)
    return enforcer


def enforcement_guardrail(enforcer: Any = None) -> "ToolInputGuardrail":
    """A ToolInputGuardrail enforcing Gentrail policy on every call of the
    tools it is attached to. enforcer is a PolicyEnforcer or
    AsyncPolicyEnforcer; None builds one from the environment and raises when
    enforcement is not configured, since silently attaching a no-op guardrail
    would look protected without being so."""
    active = _as_async(enforcer if enforcer is not None else PolicyEnforcer.from_env())
    if active is None:
        raise RuntimeError(_UNCONFIGURED)

    from agents.tool_guardrails import ToolGuardrailFunctionOutput, ToolInputGuardrail

    async def run(data: Any) -> Any:
        tool_name, tool_args, call_id, agent_name = _call_facts(data)
        allowed, message = await enforce_async(
            active,
            tool_name,
            tool_args,
            agent_id=agent_name,
            invocation_id=ambient_otel_trace_id(),
            request_id=call_id,
        )
        if allowed:
            return ToolGuardrailFunctionOutput.allow()
        return ToolGuardrailFunctionOutput.reject_content(message=message)

    return ToolInputGuardrail(guardrail_function=run, name="gentrail_enforcement")
