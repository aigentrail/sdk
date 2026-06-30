"""Decision journal — sealed evidence packages for compliance."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


class ToolCallRecord(BaseModel):
    tool_name: str
    tool_args: dict[str, Any]
    result: Optional[str] = None
    duration_ms: Optional[float] = None


class ModelCallRecord(BaseModel):
    model_id: str = ""
    prompt_preview: str = ""
    cot_reasoning: str = ""
    token_usage: dict[str, int] = Field(default_factory=dict)
    latency_ms: Optional[float] = None


class DecisionJournal(BaseModel):
    journal_id: str = Field(default_factory=lambda: f"inv-{datetime.now(timezone.utc).strftime('%Y-%m%d')}-{uuid.uuid4().hex[:6]}")
    agent_id: str
    agent_name: str
    started_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    user_message: str = ""
    final_response: str = ""
    model_calls: list[ModelCallRecord] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    total_tokens: int = 0
    sealed: bool = False
    integrity_hash: Optional[str] = None

    def seal(self) -> str:
        self.completed_at = datetime.now(timezone.utc)
        self.sealed = True
        data = self.model_dump_json(exclude={"integrity_hash"})
        self.integrity_hash = hashlib.sha256(data.encode()).hexdigest()
        return self.integrity_hash


class EvidenceLedger:
    """Stores sealed decision journals."""

    def __init__(self):
        self._journals: dict[str, DecisionJournal] = {}

    def create(self, agent_id: str, agent_name: str) -> DecisionJournal:
        journal = DecisionJournal(agent_id=agent_id, agent_name=agent_name)
        self._journals[journal.journal_id] = journal
        return journal

    def get(self, journal_id: str) -> DecisionJournal | None:
        return self._journals.get(journal_id)

    def get_all(self) -> list[DecisionJournal]:
        return list(self._journals.values())

    def get_by_agent(self, agent_id: str) -> list[DecisionJournal]:
        return [j for j in self._journals.values() if j.agent_id == agent_id]

    def seal(self, journal_id: str) -> str | None:
        journal = self._journals.get(journal_id)
        if journal:
            return journal.seal()
        return None

    def clear(self) -> None:
        self._journals.clear()


# Singleton
evidence_ledger = EvidenceLedger()
