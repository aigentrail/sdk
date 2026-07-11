"""Gentrail Governance Hook — Tier 4 compliance-evidence-grade telemetry capture.

Implements Strands HookProvider to intercept every lifecycle event and capture:
- Exact prompts sent to model
- Full Chain-of-Thought reasoning
- Tool call arguments and results
- Sealed decision journals for forensic evidence
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from strands.hooks import HookProvider, HookRegistry
from strands.hooks.events import (
    AfterInvocationEvent,
    AfterModelCallEvent,
    AfterToolCallEvent,
    BeforeInvocationEvent,
    BeforeModelCallEvent,
    BeforeToolCallEvent,
)

from .event_normalizer import AgentEvent, EventStore, EventType, SourceTier, event_store
from .evidence_ledger import (
    DecisionJournal,
    EvidenceLedger,
    ModelCallRecord,
    ToolCallRecord,
    evidence_ledger,
)
from .enforcement import PolicyEnforcer
from .otel_exporter import GovernanceTracer

logger = logging.getLogger("gentrail.hooks")


class GentrailGovernanceHook(HookProvider):
    """Tier 4: Compliance-evidence-grade telemetry capture."""

    def __init__(
        self,
        event_store_instance: EventStore | None = None,
        ledger: EvidenceLedger | None = None,
        otel_tracer: GovernanceTracer | None = None,
        enforcer: "PolicyEnforcer | None" = None,
    ):
        self.events = event_store_instance or event_store
        self.ledger = ledger or evidence_ledger
        self._otel = otel_tracer
        # Opt-in inline enforcement; None (the default) keeps capture-only behaviour.
        self._enforcer = enforcer if enforcer is not None else PolicyEnforcer.from_env()

        self._current_journal: DecisionJournal | None = None
        self._tool_call_count = 0
        self._model_call_start: float | None = None
        self._tool_call_start: float | None = None
        self._invocation_span: Any | None = None
        self._accumulated_usage_before_model_call: dict[str, int] | None = None
        self._system_prompt: str = ""
        # Non-ALLOW verdicts from the before-tool-call hook, keyed by toolUseId
        # (tool name when absent), consumed when the tool span records so it
        # carries aigentrail.enforcement.decision - the marker the evaluator
        # uses to stamp the resulting violation outcome=prevented.
        self._enforced_decisions: dict[str, str] = {}

    def register_hooks(self, registry: HookRegistry) -> None:
        registry.add_callback(BeforeInvocationEvent, self.capture_invocation_start)
        registry.add_callback(BeforeModelCallEvent, self.capture_prompt_and_context)
        registry.add_callback(AfterModelCallEvent, self.capture_cot_reasoning)
        registry.add_callback(BeforeToolCallEvent, self.capture_tool_call_start)
        registry.add_callback(AfterToolCallEvent, self.capture_tool_result)
        registry.add_callback(AfterInvocationEvent, self.seal_decision_journal)

    def capture_invocation_start(self, event: BeforeInvocationEvent) -> None:
        agent_id = event.agent.agent_id
        agent_name = event.agent.name

        self._tool_call_count = 0
        self._enforced_decisions = {}
        self._current_journal = self.ledger.create(agent_id, agent_name)

        user_msg = ""
        if event.messages:
            for msg in event.messages:
                if isinstance(msg, dict) and msg.get("role") == "user":
                    content = msg.get("content", "")
                    if isinstance(content, list):
                        for block in content:
                            if isinstance(block, dict) and block.get("text"):
                                user_msg = block["text"]
                                break
                    elif isinstance(content, str):
                        user_msg = content

        self._current_journal.user_message = user_msg[:500]

        if self._otel:
            self._invocation_span = self._otel.start_invocation(
                agent_id=agent_id,
                agent_name=agent_name,
                journal_id=self._current_journal.journal_id,
                user_message=user_msg,
            )

        self.events.append(AgentEvent(
            agent_id=agent_id,
            agent_name=agent_name,
            event_type=EventType.INVOCATION_START,
            source_tier=SourceTier.T4,
            decision_journal_id=self._current_journal.journal_id,
            payload={"user_message": user_msg[:300]},
        ))

        logger.info(f"[T4] Invocation started: journal={self._current_journal.journal_id}")

    def capture_prompt_and_context(self, event: BeforeModelCallEvent) -> None:
        agent_id = event.agent.agent_id
        agent_name = event.agent.name

        self._model_call_start = time.time()

        metrics = getattr(event.agent, "event_loop_metrics", None)
        if metrics:
            acc = getattr(metrics, "accumulated_usage", {})
            self._accumulated_usage_before_model_call = {
                "inputTokens": acc.get("inputTokens", 0),
                "outputTokens": acc.get("outputTokens", 0),
            }
        else:
            self._accumulated_usage_before_model_call = None

        self._system_prompt = getattr(event.agent, "system_prompt", "") or ""

        self.events.append(AgentEvent(
            agent_id=agent_id,
            agent_name=agent_name,
            event_type=EventType.PROMPT_CAPTURE,
            source_tier=SourceTier.T4,
            decision_journal_id=self._current_journal.journal_id if self._current_journal else None,
            payload={"invocation_state_keys": list(event.invocation_state.keys())},
        ))

    def capture_cot_reasoning(self, event: AfterModelCallEvent) -> None:
        agent_id = event.agent.agent_id
        agent_name = event.agent.name

        latency_ms = None
        if self._model_call_start:
            latency_ms = (time.time() - self._model_call_start) * 1000
            self._model_call_start = None

        cot_text = ""
        stop_reason = ""

        if event.stop_response:
            stop_reason = str(event.stop_response.stop_reason or "")
            message = event.stop_response.message
            if isinstance(message, dict):
                content = message.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("text"):
                            cot_text += block["text"]

        model_config = getattr(getattr(event.agent, "model", None), "config", {}) or {}
        model_id = model_config.get("model_id", "")

        input_tokens = 0
        output_tokens = 0
        metrics = getattr(event.agent, "event_loop_metrics", None)
        if metrics and self._accumulated_usage_before_model_call is not None:
            acc = getattr(metrics, "accumulated_usage", {})
            input_tokens = acc.get("inputTokens", 0) - self._accumulated_usage_before_model_call.get("inputTokens", 0)
            output_tokens = acc.get("outputTokens", 0) - self._accumulated_usage_before_model_call.get("outputTokens", 0)
        self._accumulated_usage_before_model_call = None

        token_usage = {"input_tokens": input_tokens, "output_tokens": output_tokens}

        if self._current_journal:
            self._current_journal.total_tokens += input_tokens + output_tokens

        record = ModelCallRecord(
            model_id=model_id,
            prompt_preview=cot_text[:300],
            cot_reasoning=cot_text[:1000],
            token_usage=token_usage,
            latency_ms=latency_ms,
        )

        if self._current_journal:
            self._current_journal.model_calls.append(record)

        if self._otel and self._invocation_span:
            self._otel.record_model_call(
                self._invocation_span,
                model_id=model_id,
                prompt=self._system_prompt[:500],
                response_text=cot_text[:1000],
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                latency_ms=latency_ms,
            )

        self.events.append(AgentEvent(
            agent_id=agent_id,
            agent_name=agent_name,
            event_type=EventType.COT_REASONING,
            source_tier=SourceTier.T4,
            decision_journal_id=self._current_journal.journal_id if self._current_journal else None,
            payload={
                "cot_preview": cot_text[:300],
                "stop_reason": stop_reason,
                "latency_ms": latency_ms,
            },
        ))

    def capture_tool_call_start(self, event: BeforeToolCallEvent) -> None:
        agent_id = event.agent.agent_id
        agent_name = event.agent.name

        self._tool_call_count += 1
        self._tool_call_start = time.time()

        tool_name = event.tool_use.get("name", "unknown")

        self.events.append(AgentEvent(
            agent_id=agent_id,
            agent_name=agent_name,
            event_type=EventType.TOOL_CALL,
            source_tier=SourceTier.T4,
            decision_journal_id=self._current_journal.journal_id if self._current_journal else None,
            payload={"tool_name": tool_name},
        ))

        logger.info(f"[T4] Tool call: {tool_name}")

        # Inline enforcement (opt-in): ask the backend before the tool runs and
        # stop it when policy says so. cancel_tool turns the call into an error
        # tool result, so the tool never executes and the agent sees the verdict.
        # BLOCK is a hard stop. GATE means "needs human approval"; without an
        # approval channel yet it also stops the call (block-pending-approval) -
        # a real gate would pause and resume on approval (a follow-up).
        if self._enforcer is not None:
            tool_args = event.tool_use.get("input", {}) or {}
            verdict = self._enforcer.decide(tool_name, tool_args)
            decision = verdict.get("decision")
            if decision in ("BLOCK", "GATE"):
                rule = verdict.get("rule", "")
                msg = verdict.get("message") or f"{decision} by policy {rule}".strip()
                event.cancel_tool = msg
                key = event.tool_use.get("toolUseId") or tool_name
                self._enforced_decisions[key] = decision
                logger.warning("[T4] %s tool %s (rule=%s): %s", decision, tool_name, rule, msg)

    def capture_tool_result(self, event: AfterToolCallEvent) -> None:
        agent_id = event.agent.agent_id
        agent_name = event.agent.name

        latency_ms = None
        if self._tool_call_start:
            latency_ms = (time.time() - self._tool_call_start) * 1000
            self._tool_call_start = None

        tool_name = event.tool_use.get("name", "unknown")
        tool_args = event.tool_use.get("input", {})
        result_str = ""
        if event.result:
            if isinstance(event.result, dict):
                content = event.result.get("content", [])
                if isinstance(content, list):
                    for block in content:
                        if isinstance(block, dict) and block.get("text"):
                            result_str += block["text"]
                elif isinstance(content, str):
                    result_str = content
            else:
                result_str = str(event.result)[:500]

        if self._current_journal:
            self._current_journal.tool_calls.append(ToolCallRecord(
                tool_name=tool_name,
                tool_args=tool_args if isinstance(tool_args, dict) else {},
                result=result_str[:200],
                duration_ms=latency_ms,
            ))

        if self._otel and self._invocation_span:
            key = event.tool_use.get("toolUseId") or tool_name
            self._otel.record_tool_call(
                self._invocation_span,
                agent_id=agent_id,
                agent_name=agent_name,
                name=tool_name,
                args=json.dumps(tool_args if isinstance(tool_args, dict) else {})[:500],
                result=result_str[:500],
                duration_ms=latency_ms,
                enforced_decision=self._enforced_decisions.pop(key, None),
            )

        self.events.append(AgentEvent(
            agent_id=agent_id,
            agent_name=agent_name,
            event_type=EventType.TOOL_RESULT,
            source_tier=SourceTier.T4,
            decision_journal_id=self._current_journal.journal_id if self._current_journal else None,
            payload={
                "tool_name": tool_name,
                "result_preview": result_str[:200],
                "duration_ms": latency_ms,
            },
        ))

    def seal_decision_journal(self, event: AfterInvocationEvent) -> None:
        if not self._current_journal:
            return

        agent_id = event.agent.agent_id
        agent_name = event.agent.name

        final_response = ""
        if event.result:
            final_response = str(event.result)[:500]
        self._current_journal.final_response = final_response

        integrity_hash = self.ledger.seal(self._current_journal.journal_id)

        if self._otel and self._invocation_span:
            self._otel.end_invocation(
                self._invocation_span,
                response=final_response,
                total_tokens=self._current_journal.total_tokens,
                tool_count=self._tool_call_count,
                integrity_hash=integrity_hash,
            )
            # Force a flush so the invocation span ships in the same OTLP
            # batch as the trailing tool_calls. Without this, BatchSpanProcessor's
            # 5s schedule can split a long invocation across requests, leaving
            # the parent trace not yet in DDB when its tool_calls arrive.
            self._otel.force_flush()
            self._invocation_span = None

        self.events.append(AgentEvent(
            agent_id=agent_id,
            agent_name=agent_name,
            event_type=EventType.EVIDENCE_SEAL,
            source_tier=SourceTier.T4,
            decision_journal_id=self._current_journal.journal_id,
            payload={
                "journal_id": self._current_journal.journal_id,
                "total_tokens": self._current_journal.total_tokens,
                "tool_calls": self._tool_call_count,
                "integrity_hash": integrity_hash,
            },
        ))

        logger.info(
            f"[T4] Journal sealed: {self._current_journal.journal_id} "
            f"| tools={self._tool_call_count}"
        )
        self._current_journal = None
