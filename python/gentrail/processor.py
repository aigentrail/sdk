"""Span enrichment and PII redaction for apps that bring their own telemetry.

Frameworks that emit GenAI telemetry natively (gen_ai.* semconv, Vercel ai.*,
OpenInference) no longer need the SDK to build spans; the backend ingests them
directly. GentrailSpanProcessor adds what only the client can: PII redaction
before attribute values leave the process, an aigentrail.redaction.applied
stamp on spans it changed, and OTLP export to the Gentrail collector.
Enforcement decisions are never stamped here; the enforcement adapters own
aigentrail.enforcement.decision.

Where redaction happens: on_start only sees the attributes present at span
creation, and the GenAI output attributes are set later; on_end receives a
ReadableSpan whose attributes are an immutable mapping proxy, so mutation there
is unsupported and would anyway be visible to every other processor on the
provider. The one point where the SDK owns the data and every attribute is
final is its own export path, so redaction rewrites attributes on a per-span
copy inside a wrapping exporter, immediately before OTLP encoding. The app's
other exporters keep the raw span.
"""

from __future__ import annotations

from typing import Any

from opentelemetry.sdk.trace import ReadableSpan, SpanProcessor
from opentelemetry.sdk.trace.export import BatchSpanProcessor

from . import otel_exporter as _otel
from .export_filter import GenAISignalExporter

_REDACTED_ATTR_PREFIXES = ("gen_ai.", "ai.", "input.", "output.")


def _redact_attr_value(value: Any) -> Any:
    if isinstance(value, str):
        return _otel.redact_pii(value)
    if isinstance(value, (list, tuple)):
        return tuple(_otel.redact_pii(v) if isinstance(v, str) else v for v in value)
    return value


def _redacted_copy(span: Any) -> Any:
    attrs = span.attributes or {}
    replaced = {}
    for key, value in attrs.items():
        if not key.startswith(_REDACTED_ATTR_PREFIXES):
            continue
        redacted = _redact_attr_value(value)
        if redacted != value:
            replaced[key] = redacted
    if not replaced:
        return span
    merged = dict(attrs)
    merged.update(replaced)
    merged["aigentrail.redaction.applied"] = True
    return ReadableSpan(
        name=span.name,
        context=span.get_span_context(),
        parent=span.parent,
        resource=span.resource,
        attributes=merged,
        events=span.events,
        links=span.links,
        kind=span.kind,
        status=span.status,
        start_time=span.start_time,
        end_time=span.end_time,
        instrumentation_scope=span.instrumentation_scope,
    )


class _RedactingExporter:
    def __init__(self, wrapped: Any):
        self._wrapped = wrapped

    def export(self, spans: Any) -> Any:
        return self._wrapped.export([_redacted_copy(s) for s in spans])

    def shutdown(self) -> Any:
        return self._wrapped.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> Any:
        return self._wrapped.force_flush(timeout_millis)


class GentrailSpanProcessor(SpanProcessor):
    """SpanProcessor that batch-exports to Gentrail, redacting PII from
    gen_ai.*, ai.*, and OpenInference input/output attributes on the way out.

    exporter defaults to the OTLP exporter built from GENTRAIL_API_KEY and
    OTEL_EXPORTER_OTLP_ENDPOINT; inject one for tests. redact defaults on
    unless GENTRAIL_REDACT_PII=false.
    """

    def __init__(self, exporter: Any | None = None, redact: bool | None = None):
        if redact is None:
            redact = _otel._redact_enabled_from_env()
        if exporter is None:
            api_key = _otel._api_key_from_env()
            if not api_key:
                raise RuntimeError("GentrailSpanProcessor requires GENTRAIL_API_KEY")
            exporter = _otel._build_otlp_exporter(api_key)
            if exporter is None:
                raise RuntimeError(
                    "GentrailSpanProcessor requires opentelemetry-exporter-otlp-proto-http"
                )
        self._batch = BatchSpanProcessor(GenAISignalExporter(_RedactingExporter(exporter) if redact else exporter))

    def on_start(self, span: Any, parent_context: Any = None) -> None:
        self._batch.on_start(span, parent_context)

    def on_end(self, span: Any) -> None:
        self._batch.on_end(span)

    def shutdown(self) -> None:
        self._batch.shutdown()

    def force_flush(self, timeout_millis: int = 30000) -> bool:
        return self._batch.force_flush(timeout_millis)


def instrument(provider: Any | None = None, redact: bool | None = None) -> GentrailSpanProcessor | None:
    """Attach a GentrailSpanProcessor to the app's TracerProvider.

    With no provider argument it attaches to the global provider, installing a
    fresh one only when none exists. Returns None without error when
    GENTRAIL_API_KEY is unset or opentelemetry is not installed, so an
    instrumented app still runs unconfigured.
    """
    api_key = _otel._api_key_from_env()
    if not api_key:
        return None
    if not _otel._try_import_otel():
        return None
    processor = GentrailSpanProcessor(redact=redact)
    if provider is not None:
        provider.add_span_processor(processor)
    else:
        _otel._attach_or_install_provider(processor)
    return processor
