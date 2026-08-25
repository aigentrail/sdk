"""One-line SDK setup.

gentrail.init() reads GENTRAIL_API_KEY, GENTRAIL_DECIDE_ENDPOINT, and
OTEL_EXPORTER_OTLP_ENDPOINT, builds the governance tracer and the policy
enforcer, and returns a handle whose hook() plugs straight into
strands Agent(hooks=[...]).
"""

from __future__ import annotations

from typing import Any

from .enforcement import PolicyEnforcer
from .otel_exporter import GovernanceTracer, get_governance_tracer


class Gentrail:
    """Handle returned by init(): the configured tracer and enforcer, plus a
    hook() factory for strands agents."""

    def __init__(self, tracer: GovernanceTracer | None, enforcer: PolicyEnforcer | None):
        self.tracer = tracer
        self.enforcer = enforcer

    def hook(self) -> Any:
        """A fresh GentrailGovernanceHook wired to this handle's tracer and
        enforcer. One hook per agent: the hook carries per-invocation state.
        Requires the strands extra."""
        from .hooks import GentrailGovernanceHook

        return GentrailGovernanceHook(otel_tracer=self.tracer, enforcer=self.enforcer)

    def flush(self) -> None:
        if self.tracer:
            self.tracer.force_flush()

    def shutdown(self) -> None:
        if self.tracer:
            self.tracer.shutdown()


def init() -> Gentrail:
    """Configure the SDK from the environment.

    Tracing needs GENTRAIL_API_KEY (endpoint override via
    OTEL_EXPORTER_OTLP_ENDPOINT); inline enforcement additionally needs
    GENTRAIL_DECIDE_ENDPOINT. Whatever is unset stays off: the returned handle
    always works, degrading to local capture only.
    """
    return Gentrail(tracer=get_governance_tracer(), enforcer=PolicyEnforcer.from_env())
