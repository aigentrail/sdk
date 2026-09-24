"""Decision journal: sealed evidence packages for compliance."""

from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field

from .canonical_json import canonical_json


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

    def seal(self, now: Optional[datetime] = None) -> str:
        self.completed_at = now or datetime.now(timezone.utc)
        self.sealed = True
        self.integrity_hash = journal_integrity_hash(self)
        return self.integrity_hash


def journal_canonical_document(journal: DecisionJournal) -> dict[str, Any]:
    return {
        "journal_id": journal.journal_id,
        "agent_id": journal.agent_id,
        "agent_name": journal.agent_name,
        "started_at": _utc_millis(journal.started_at),
        "completed_at": _utc_millis(journal.completed_at) if journal.completed_at else None,
        "user_message": journal.user_message,
        "final_response": journal.final_response,
        "model_calls": [
            {
                "model_id": call.model_id,
                "prompt_preview": call.prompt_preview,
                "cot_reasoning": call.cot_reasoning,
                "token_usage": dict(call.token_usage),
                "latency_ms": call.latency_ms,
            }
            for call in journal.model_calls
        ],
        "tool_calls": [
            {
                "tool_name": call.tool_name,
                "tool_args": call.tool_args,
                "result": call.result,
                "duration_ms": call.duration_ms,
            }
            for call in journal.tool_calls
        ],
        "total_tokens": journal.total_tokens,
        "sealed": journal.sealed,
    }


def journal_integrity_hash(journal: DecisionJournal) -> str:
    canonical = canonical_json(journal_canonical_document(journal))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _utc_millis(moment: datetime) -> str:
    assert moment.tzinfo is not None, "journal timestamps must be timezone-aware"
    utc = moment.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


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
