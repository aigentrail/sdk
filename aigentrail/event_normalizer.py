"""Canonical AgentEvent schema — normalizes data from all integration tiers."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


class SourceTier(str, Enum):
    T3A = "T3a"
    T4 = "T4"


class EventType(str, Enum):
    INVOCATION_START = "invocation_start"
    PROMPT_CAPTURE = "prompt_capture"
    COT_REASONING = "cot_reasoning"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    EVIDENCE_SEAL = "evidence_seal"
    AGENT_REGISTERED = "agent_registered"


class AgentEvent(BaseModel):
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    agent_id: str
    agent_name: str = ""
    event_type: EventType
    source_tier: SourceTier
    payload: dict[str, Any] = Field(default_factory=dict)
    decision_journal_id: Optional[str] = None
    integrity_hash: Optional[str] = None

    def compute_hash(self) -> str:
        data = self.model_dump_json(exclude={"integrity_hash"})
        self.integrity_hash = hashlib.sha256(data.encode()).hexdigest()
        return self.integrity_hash


class EventStore:
    """In-memory event store."""

    def __init__(self):
        self._events: list[AgentEvent] = []
        self._subscribers: list[Any] = []

    def append(self, event: AgentEvent) -> None:
        event.compute_hash()
        self._events.append(event)
        for callback in self._subscribers:
            try:
                callback(event)
            except Exception:
                pass

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def get_all(self) -> list[AgentEvent]:
        return list(self._events)

    def get_by_agent(self, agent_id: str) -> list[AgentEvent]:
        return [e for e in self._events if e.agent_id == agent_id]

    def get_by_journal(self, journal_id: str) -> list[AgentEvent]:
        return [e for e in self._events if e.decision_journal_id == journal_id]

    def get_by_type(self, event_type: EventType) -> list[AgentEvent]:
        return [e for e in self._events if e.event_type == event_type]

    def clear(self) -> None:
        self._events.clear()


# Singleton
event_store = EventStore()
