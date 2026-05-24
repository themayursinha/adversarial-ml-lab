"""OpenTelemetry tracing for defense pipeline observability.

Adds distributed traces across canonicalization, anomaly scoring,
context filtering, uncertainty scoring, and LLM generation stages.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Any, Iterator

import structlog

log = structlog.get_logger(__name__)

_tracer: Any = None
_initialized = False


def _init_tracing() -> None:
    global _tracer, _initialized
    if _initialized:
        return
    _initialized = True

    try:
        from opentelemetry import trace
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        endpoint = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        if endpoint:
            exporter = OTLPSpanExporter(endpoint=endpoint)
            provider = TracerProvider()
            provider.add_span_processor(BatchSpanProcessor(exporter))
            trace.set_tracer_provider(provider)
            _tracer = trace.get_tracer("adversarial-ml-lab")
            log.info("tracing.enabled", endpoint=endpoint)
        else:
            _tracer = trace.get_tracer("adversarial-ml-lab")
    except ImportError:
        from opentelemetry import trace

        _tracer = trace.get_tracer("adversarial-ml-lab")


def get_tracer() -> Any:
    global _tracer
    if _tracer is None:
        _init_tracing()
    return _tracer


@contextmanager
def trace_span(name: str, **attributes: Any) -> Iterator[Any]:
    tracer = get_tracer()
    with tracer.start_as_current_span(name) as span:
        if attributes:
            span.set_attributes(attributes)
        yield span


def trace_pipeline_stage(stage: str) -> Any:
    """Decorator to trace a pipeline stage function."""

    def decorator(func: Any) -> Any:
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            with trace_span(f"pipeline.{stage}"):
                return func(*args, **kwargs)

        return wrapper

    return decorator
