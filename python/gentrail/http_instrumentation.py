"""httpx transports that record each request as a one-shot governance LLM
call, the Python counterpart of the Go SDK's HTTPRoundTripper. Use them on an
LLM-specific client for zero-touch latency and status capture; for model name,
prompt, and tokens call GovernanceTracer.record_model_call instead."""

from __future__ import annotations

import time
from typing import Any


def _call_status(response: Any | None) -> str:
    if response is None:
        return "error"
    if response.status_code >= 400:
        return f"http_{response.status_code}"
    return "ok"


def _record(tracer: Any, request: Any, response: Any | None, started_at: float) -> None:
    status = _call_status(response)
    tracer.record_llm_call(
        agent_id="",
        agent_name="",
        model_id=request.url.host,
        prompt=f"{request.method} {request.url.path}",
        response_text=status,
        latency_ms=float(int((time.monotonic() - started_at) * 1000)),
        status=status,
    )


def governance_transport(tracer: Any, base: Any | None = None) -> Any:
    import httpx

    class GovernanceTransport(httpx.BaseTransport):
        def __init__(self, wrapped: httpx.BaseTransport) -> None:
            self._wrapped = wrapped

        def handle_request(self, request: httpx.Request) -> httpx.Response:
            started_at = time.monotonic()
            try:
                response = self._wrapped.handle_request(request)
            except Exception:
                _record(tracer, request, None, started_at)
                raise
            _record(tracer, request, response, started_at)
            return response

        def close(self) -> None:
            self._wrapped.close()

    return GovernanceTransport(base if base is not None else httpx.HTTPTransport())


def async_governance_transport(tracer: Any, base: Any | None = None) -> Any:
    import httpx

    class AsyncGovernanceTransport(httpx.AsyncBaseTransport):
        def __init__(self, wrapped: httpx.AsyncBaseTransport) -> None:
            self._wrapped = wrapped

        async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
            started_at = time.monotonic()
            try:
                response = await self._wrapped.handle_async_request(request)
            except Exception:
                _record(tracer, request, None, started_at)
                raise
            _record(tracer, request, response, started_at)
            return response

        async def aclose(self) -> None:
            await self._wrapped.aclose()

    return AsyncGovernanceTransport(base if base is not None else httpx.AsyncHTTPTransport())
