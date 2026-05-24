"""Structured logging configuration for adversarial-ml-lab."""

from __future__ import annotations

import logging
import os
import sys
from typing import Any

import structlog


def _stderr_renderer(
    _logger: Any,
    _method_name: str,
    event_dict: Any,
) -> str:
    """Minimal renderer that formats structured events for stderr output."""
    event = event_dict.pop("event", "")
    level = event_dict.pop("level", "info")
    ts = event_dict.pop("timestamp", "")
    parts = []
    if ts:
        parts.append(f"[{ts}]")
    parts.append(level.upper())
    parts.append(event)
    for k, v in event_dict.items():
        parts.append(f"{k}={v}")
    return " ".join(parts)


def configure_logging(
    level: str = "INFO",
    json_output: bool = False,
) -> None:
    """Configure structlog for the application.

    Writes structured logs to stderr (never stdout, which is reserved
    for JSON CLI output). Uses a simple key-value format that works
    across all structlog versions.

    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR).
        json_output: If True, emit JSON lines to stderr for log aggregation.
    """
    log_level = getattr(logging, level.upper(), logging.INFO)

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stderr,
        level=log_level,
    )

    structlog.reset_defaults()

    processors: list[structlog.types.Processor] = [
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.add_log_level,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.dev.set_exc_info,
    ]

    if json_output:
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(_stderr_renderer)

    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(file=sys.stderr),
        wrapper_class=structlog.BoundLogger,
        cache_logger_on_first_use=False,
    )


def configure_silent() -> None:
    """Suppress all log output for test environments."""
    structlog.reset_defaults()
    structlog.configure(
        processors=[_stderr_renderer],
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(
            file=open(os.devnull, "w"),  # noqa: SIM115
        ),
        wrapper_class=structlog.BoundLogger,
        cache_logger_on_first_use=False,
    )
