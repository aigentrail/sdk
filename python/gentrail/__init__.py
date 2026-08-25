"""Gentrail SDK: governance hooks, inline policy enforcement, and telemetry
capture for AI agents. Start with gentrail.init()."""

from .enforcement import AsyncPolicyEnforcer, PolicyEnforcer
from .init import Gentrail, init
from .otel_exporter import GovernanceTracer, create_governance_tracer, get_governance_tracer
from .processor import GentrailSpanProcessor, instrument

from .event_normalizer import AgentEvent, EventStore, EventType, SourceTier, event_store
from .evidence_ledger import (
    DecisionJournal,
    EvidenceLedger,
    ModelCallRecord,
    ToolCallRecord,
    evidence_ledger,
)

# Strands HookProvider is optional: importing strands when it is not installed
# would break SDK consumers that only need the OTLP exporter (e.g. policy_engine).
try:
    from .hooks import GentrailGovernanceHook
except ImportError:
    GentrailGovernanceHook = None  # type: ignore[assignment,misc]

__all__ = [
    "init",
    "instrument",
    "Gentrail",
    "GentrailGovernanceHook",
    "GentrailSpanProcessor",
    "AsyncPolicyEnforcer",
    "PolicyEnforcer",
    "GovernanceTracer",
    "create_governance_tracer",
    "get_governance_tracer",
    "AgentEvent",
    "DecisionJournal",
    "EventStore",
    "EventType",
    "EvidenceLedger",
    "ModelCallRecord",
    "SourceTier",
    "ToolCallRecord",
    "event_store",
    "evidence_ledger",
]
