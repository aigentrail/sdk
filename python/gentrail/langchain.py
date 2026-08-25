"""Gentrail enforcement middleware for langchain 1.0 agents.

enforcement_middleware() returns an AgentMiddleware whose wrap_tool_call and
awrap_tool_call ask the Gentrail decide endpoint before every tool call the
agent makes:

    from langchain.agents import create_agent
    from gentrail.langchain import enforcement_middleware

    agent = create_agent(
        model=model,
        tools=tools,
        middleware=[enforcement_middleware(agent_id="reporter")],
    )

BLOCK short-circuits the handler and returns a ToolMessage with
status="error" carrying the policy message, so the tool never executes and
the model sees why.

GATE mapping: langgraph.interrupt() would pause the graph and hand the
approve/resume decision to the calling application via Command(resume=...),
which needs a checkpointer and an application-side approval channel. A
Gentrail gate is decided in the Gentrail dashboard against a durable approval
hold, so the middleware holds the tool call and polls that hold's status URL
instead, running the tool on approval and cancelling it otherwise. No
checkpointer, no resume plumbing, and BLOCK and GATE ride the same seam.

The middleware sends the enforcement identity fields the backend joins on:
agent_id from the factory argument, request_id from the tool call id, and
invocation_id from the ambient OpenTelemetry trace when the process is
OTel-instrumented.

Importing this module never imports the langchain package; the factory does,
so only callers that build the middleware need the langchain install.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Callable

from .enforcement import (
    AsyncPolicyEnforcer,
    PolicyEnforcer,
    ambient_otel_trace_id,
    enforce,
    enforce_async,
)

if TYPE_CHECKING:
    from langchain.agents.middleware import AgentMiddleware

_UNCONFIGURED = (
    "gentrail enforcement is not configured: "
    "set GENTRAIL_DECIDE_ENDPOINT and GENTRAIL_API_KEY"
)


def _wrap_tool_call(
    request: Any,
    handler: Callable[[Any], Any],
    enforcer: Any,
    agent_id: str,
    cancel: Callable[[str, dict], Any],
) -> Any:
    tool_call = request.tool_call
    allowed, message = enforce(
        enforcer,
        tool_call.get("name") or "",
        tool_call.get("args") or {},
        agent_id=agent_id,
        invocation_id=ambient_otel_trace_id(),
        request_id=tool_call.get("id") or "",
    )
    if not allowed:
        return cancel(message, tool_call)
    return handler(request)


async def _awrap_tool_call(
    request: Any,
    handler: Callable[[Any], Any],
    enforcer: Any,
    agent_id: str,
    cancel: Callable[[str, dict], Any],
) -> Any:
    tool_call = request.tool_call
    allowed, message = await enforce_async(
        enforcer,
        tool_call.get("name") or "",
        tool_call.get("args") or {},
        agent_id=agent_id,
        invocation_id=ambient_otel_trace_id(),
        request_id=tool_call.get("id") or "",
    )
    if not allowed:
        return cancel(message, tool_call)
    return await handler(request)


def enforcement_middleware(enforcer: Any = None, *, agent_id: str = "") -> "AgentMiddleware":
    """An AgentMiddleware enforcing Gentrail policy on every tool call.
    enforcer is a PolicyEnforcer or AsyncPolicyEnforcer; None builds one from
    the environment and raises when enforcement is not configured, since
    silently attaching a no-op middleware would look protected without being
    so. agent_id scopes agent-targeted and windowed rules to this agent."""
    if enforcer is None:
        enforcer = PolicyEnforcer.from_env()
    if enforcer is None:
        raise RuntimeError(_UNCONFIGURED)

    from langchain.agents.middleware import AgentMiddleware
    from langchain.messages import ToolMessage
    if isinstance(enforcer, AsyncPolicyEnforcer):
        sync = PolicyEnforcer(enforcer.base, enforcer.api_key, enforcer.timeout)
        async_twin = enforcer
    elif isinstance(enforcer, PolicyEnforcer):
        sync = enforcer
        async_twin = AsyncPolicyEnforcer(enforcer.base, enforcer.api_key, enforcer.timeout)
    else:
        sync = enforcer
        async_twin = enforcer

    def cancel(message: str, tool_call: dict) -> Any:
        return ToolMessage(
            content=message,
            tool_call_id=tool_call.get("id") or "",
            name=tool_call.get("name") or "",
            status="error",
        )

    class GentrailEnforcementMiddleware(AgentMiddleware):
        def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
            return _wrap_tool_call(request, handler, sync, agent_id, cancel)

        async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any]) -> Any:
            return await _awrap_tool_call(request, handler, async_twin, agent_id, cancel)

    return GentrailEnforcementMiddleware()
