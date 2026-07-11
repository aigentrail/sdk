"""OTel span exporter for governance events.

Enabled by default when GENTRAIL_API_KEY is set.
Exports to https://otel.gentrail.ai unless overridden by
OTEL_EXPORTER_OTLP_ENDPOINT.
"""

from __future__ import annotations

import base64
import logging
import os
import re
import threading
from typing import Any

logger = logging.getLogger("gentrail.otel")

# --- Client-side PII redaction ------------------------------------------------
# High-confidence PII in span input/output values is replaced with a typed
# placeholder before the span leaves the process, so the raw value never reaches
# the collector while the data class stays visible for governance. On by
# default; disable with GENTRAIL_REDACT_PII=false or create_governance_tracer(
# redact=False). Mirrors the Go SDK's redaction.
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")
_SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[0-9A-Z]{16}\b")
# A card candidate is 13-19 digits with optional space/dash separators; the Luhn
# check keeps random long numbers from being redacted.
_CARD_RE = re.compile(r"\b\d(?:[ -]?\d){12,18}\b")


def _luhn_valid(s: str) -> bool:
    """Report whether the 13-19 digits in s pass the Luhn checksum."""
    digits = [ord(c) - 48 for c in s if "0" <= c <= "9"]
    if not 13 <= len(digits) <= 19:
        return False
    total, double = 0, False
    for d in reversed(digits):
        if double:
            d *= 2
            if d > 9:
                d -= 9
        total += d
        double = not double
    return total % 10 == 0


def _card_placeholder(m: "re.Match[str]") -> str:
    return "[CREDIT_CARD]" if _luhn_valid(m.group(0)) else m.group(0)


def redact_pii(s: str) -> str:
    """Replace high-confidence PII in s with a typed placeholder. Emails and SSNs
    are removed before the card scan so their digits can't be mistaken for a card.
    """
    if not s:
        return s
    s = _EMAIL_RE.sub("[EMAIL]", s)
    s = _SSN_RE.sub("[SSN]", s)
    s = _AWS_KEY_RE.sub("[AWS_KEY]", s)
    s = _CARD_RE.sub(_card_placeholder, s)
    return s

# Lazy-loaded OTel modules — None until _try_import_otel() succeeds.
_trace_mod: Any = None
_sdk_trace_mod: Any = None
_otlp_exporter_mod: Any = None
_batch_processor_mod: Any = None
_status_mod: Any = None


def _try_import_otel() -> bool:
    """Import OTel packages. Returns True on success, False if not installed."""
    global _trace_mod, _sdk_trace_mod, _otlp_exporter_mod, _batch_processor_mod, _status_mod
    if _trace_mod is not None:
        return True
    try:
        import opentelemetry.trace as trace_mod
        import opentelemetry.sdk.trace as sdk_trace_mod
        from opentelemetry.sdk.trace import export as batch_processor_mod
        from opentelemetry.exporter.otlp.proto.http import trace_exporter as otlp_exporter_mod
        from opentelemetry.trace import status as status_mod

        _trace_mod = trace_mod
        _sdk_trace_mod = sdk_trace_mod
        _otlp_exporter_mod = otlp_exporter_mod
        _batch_processor_mod = batch_processor_mod
        _status_mod = status_mod
        return True
    except ImportError:
        return False


class GovernanceTracer:
    """Wraps an OTel Tracer to emit governance-specific spans."""

    def __init__(self, tracer: Any, provider: Any, redact: bool = True) -> None:
        self._tracer = tracer
        self._provider = provider
        self._redact = redact

    def _value(self, s: str) -> str:
        """Redact PII (when enabled) then cap at the 4000-rune attribute limit.
        Redaction runs first so a value straddling the cap is still scrubbed."""
        if self._redact:
            s = redact_pii(s)
        return s[:4000]

    def start_invocation(
        self,
        agent_id: str,
        agent_name: str,
        journal_id: str,
        user_message: str,
    ) -> Any:
        span = self._tracer.start_span("governance.invocation")
        span.set_attribute("openinference.span.kind", "AGENT")
        span.set_attribute("aigentrail.agent.id", agent_id)
        span.set_attribute("agent.name", agent_name)
        span.set_attribute("aigentrail.journal.id", journal_id)
        span.set_attribute("session.id", journal_id)
        span.set_attribute("input.value", self._value(user_message))
        span.set_attribute("source", "aigentrail-sdk")
        return span

    def end_invocation(
        self,
        span: Any,
        *,
        response: str,
        total_tokens: int,
        tool_count: int,
        integrity_hash: str,
        status: str = "ok",
    ) -> None:
        span.set_attribute("output.value", self._value(response))
        span.set_attribute("aigentrail.invocation.status", status)
        span.set_attribute("aigentrail.journal.integrity_hash", integrity_hash)
        span.set_attribute("llm.token_count.total", total_tokens)
        span.set_attribute("aigentrail.tool.count", tool_count)
        span.set_status(_status_mod.Status(_status_mod.StatusCode.OK))
        span.end()

    def record_model_call(
        self,
        parent: Any,
        *,
        model_id: str,
        prompt: str,
        response_text: str,
        input_tokens: int,
        output_tokens: int,
        latency_ms: float | None,
    ) -> None:
        ctx = _trace_mod.set_span_in_context(parent)
        with self._tracer.start_as_current_span("governance.model_call", context=ctx) as span:
            span.set_attribute("openinference.span.kind", "LLM")
            span.set_attribute("llm.model_name", model_id)
            span.set_attribute("input.value", self._value(prompt))
            span.set_attribute("output.value", self._value(response_text))
            span.set_attribute("llm.token_count.prompt", input_tokens)
            span.set_attribute("llm.token_count.completion", output_tokens)
            if latency_ms is not None:
                span.set_attribute("aigentrail.latency_ms", latency_ms)

    def record_tool_call(
        self,
        parent: Any,
        *,
        agent_id: str,
        agent_name: str,
        name: str,
        args: str,
        result: str,
        duration_ms: float | None,
        enforced_decision: str | None = None,
    ) -> None:
        ctx = _trace_mod.set_span_in_context(parent)
        with self._tracer.start_as_current_span(name, context=ctx) as span:
            span.set_attribute("openinference.span.kind", "TOOL")
            span.set_attribute("tool.name", name)
            # agent_id and agent_name let the collector attach this tool_call
            # to the right invocation when the BatchSpanProcessor flushes
            # tool_calls before the parent invocation span has ended.
            span.set_attribute("aigentrail.agent.id", agent_id)
            span.set_attribute("agent.name", agent_name)
            span.set_attribute("input.value", self._value(args))
            span.set_attribute("output.value", self._value(result))
            if duration_ms is not None:
                span.set_attribute("aigentrail.latency_ms", duration_ms)
            # The pre-execution verdict that cancelled this call (BLOCK or
            # GATE). Ingestion copies it onto the tool_call item and the
            # evaluator stamps the matching violation outcome=prevented, so the
            # dashboard reads the fire as enforcement working, not a fresh alarm.
            if enforced_decision:
                span.set_attribute("aigentrail.enforcement.decision", enforced_decision)

    def record_llm_call(
        self,
        *,
        agent_id: str,
        agent_name: str,
        model_id: str,
        prompt: str,
        response_text: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        total_tokens: int = 0,
        latency_ms: float | None = None,
        status: str = "ok",
        journal_id: str | None = None,
    ) -> None:
        """One-shot LLM call: opens invocation, emits model_call child, closes.

        Mirrors the Go SDK's RecordLLMCall so single-call services (the
        policy_engine extractor, the dashboard's classifier loop) get
        parent + model_call + end without driving the span lifecycle by hand.
        journal_id is generated when not supplied.
        """
        import uuid

        journal_id = journal_id or uuid.uuid4().hex
        parent = self.start_invocation(
            agent_id=agent_id,
            agent_name=agent_name,
            journal_id=journal_id,
            user_message=prompt,
        )
        self.record_model_call(
            parent,
            model_id=model_id,
            prompt=prompt,
            response_text=response_text,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            latency_ms=latency_ms,
        )
        self.end_invocation(
            parent,
            response=response_text,
            total_tokens=total_tokens,
            tool_count=0,
            integrity_hash="",
            status=status,
        )

    def shutdown(self) -> None:
        if hasattr(self._provider, "shutdown"):
            self._provider.shutdown()

    def force_flush(self) -> None:
        if hasattr(self._provider, "force_flush"):
            self._provider.force_flush()


_singleton: GovernanceTracer | None = None
_singleton_lock = threading.Lock()
_singleton_attempted = False


DEFAULT_ENDPOINT = "https://otel.gentrail.ai"


def create_governance_tracer(redact: bool | None = None) -> GovernanceTracer | None:
    """Build a GovernanceTracer from env vars. Returns None if GENTRAIL_API_KEY is
    missing. PII redaction defaults on unless redact is passed or
    GENTRAIL_REDACT_PII=false."""
    api_key = os.environ.get("GENTRAIL_API_KEY", "")
    if not api_key:
        # Opting out by setting nothing stays silent, but half-configured
        # environments must not fail into silent no-tracing: that failure mode
        # cost a day of debugging when the aigentrail -> gentrail env rename
        # left consumers exporting the old key name.
        if os.environ.get("AIGENTRAIL_API_KEY"):
            logger.warning(
                "AIGENTRAIL_API_KEY is set but this SDK reads GENTRAIL_API_KEY; governance tracing disabled"
            )
        elif os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT"):
            logger.warning(
                "OTEL_EXPORTER_OTLP_ENDPOINT is set but GENTRAIL_API_KEY is not; governance tracing disabled"
            )
        return None

    if redact is None:
        redact = os.environ.get("GENTRAIL_REDACT_PII", "").lower() != "false"

    endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", DEFAULT_ENDPOINT)

    if not _try_import_otel():
        logger.warning("GENTRAIL_API_KEY set but opentelemetry packages not installed")
        return None

    credentials = base64.b64encode(f"{api_key}:{api_key}".encode()).decode()
    headers = {"Authorization": f"Basic {credentials}"}
    ca_cert = os.environ.get("OTEL_EXPORTER_OTLP_CERTIFICATE", "")
    insecure = os.environ.get("OTEL_EXPORTER_OTLP_INSECURE", "").lower() in ("true", "1", "yes")

    exporter_kwargs: dict[str, Any] = {
        "endpoint": f"{endpoint.rstrip('/')}/v1/traces",
        "headers": headers,
    }
    if ca_cert:
        exporter_kwargs["certificate_file"] = ca_cert

    exporter = _otlp_exporter_mod.OTLPSpanExporter(**exporter_kwargs)

    if insecure:
        # OTLPSpanExporter passes verify=_certificate_file to requests.post().
        # The constructor coerces False → True, so we override after creation.
        exporter._certificate_file = False
    provider = _sdk_trace_mod.TracerProvider()
    provider.add_span_processor(_batch_processor_mod.BatchSpanProcessor(exporter))
    _trace_mod.set_tracer_provider(provider)

    tracer = _trace_mod.get_tracer("aigentrail.governance")
    logger.info("Governance OTel tracer initialized → %s", endpoint)
    return GovernanceTracer(tracer, provider, redact=redact)


def get_governance_tracer() -> GovernanceTracer | None:
    """Return the singleton GovernanceTracer (created on first call)."""
    global _singleton, _singleton_attempted
    if _singleton is not None:
        return _singleton
    if _singleton_attempted:
        return None

    with _singleton_lock:
        if _singleton is not None:
            return _singleton
        if _singleton_attempted:
            return None
        _singleton_attempted = True
        _singleton = create_governance_tracer()
        return _singleton
