"""Gentrail SDK — governance hooks and telemetry capture for AI agents."""

from .event_normalizer import AgentEvent, EventStore, EventType, SourceTier, event_store
from .evidence_ledger import (
    DecisionJournal,
    EvidenceLedger,
    ModelCallRecord,
    ToolCallRecord,
    evidence_ledger,
)
from .otel_exporter import GovernanceTracer, create_governance_tracer, get_governance_tracer

# Strands HookProvider is optional: importing strands when it is not installed
# would break SDK consumers that only need the OTLP exporter (e.g. policy_engine).
try:
    from .hooks import GentrailGovernanceHook
except ImportError:
    GentrailGovernanceHook = None  # type: ignore[assignment,misc]

__all__ = [
    "AgentEvent",
    "GentrailGovernanceHook",
    "DecisionJournal",
    "EventStore",
    "EventType",
    "EvidenceLedger",
    "GovernanceTracer",
    "ModelCallRecord",
    "SourceTier",
    "ToolCallRecord",
    "create_governance_tracer",
    "event_store",
    "evidence_ledger",
    "get_governance_tracer",
]
