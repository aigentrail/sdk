"""Only spans Gentrail ingests leave the process: an app's HTTP and database
spans can carry PII in attributes redaction never inspects, so they are dropped
on every Gentrail export path. The lists match spec/spans.json export_filter."""

from __future__ import annotations

from typing import Any, Iterable, List

GENAI_SIGNAL_ATTRIBUTE_PREFIXES = ("gen_ai.", "ai.", "llm.", "openinference.", "aigentrail.")
GENAI_SIGNAL_ATTRIBUTE_KEYS = frozenset({"session.id", "agent.name", "tool.name"})


def carries_genai_signal(attribute_keys: Iterable[str]) -> bool:
    return any(
        key in GENAI_SIGNAL_ATTRIBUTE_KEYS or key.startswith(GENAI_SIGNAL_ATTRIBUTE_PREFIXES)
        for key in attribute_keys
    )


class GenAISignalExporter:
    """Wraps a SpanExporter, forwarding only spans that carry a GenAI signal."""

    def __init__(self, wrapped: Any) -> None:
        self._wrapped = wrapped

    def export(self, spans: Any) -> Any:
        kept: List[Any] = [span for span in spans if carries_genai_signal((span.attributes or {}).keys())]
        if not kept:
            from opentelemetry.sdk.trace.export import SpanExportResult

            return SpanExportResult.SUCCESS
        return self._wrapped.export(kept)

    def shutdown(self) -> None:
        self._wrapped.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._wrapped.force_flush(timeout_millis)
