"""Fail-closed gate for Python runtime packages required by evaluation validation."""

from __future__ import annotations

import importlib
from functools import lru_cache
from typing import Sequence

from src.eval.contract import EvaluationContractError

# PyPI distribution name -> top-level import module (when they differ).
EVALUATION_REQUIRED_PACKAGES: tuple[tuple[str, str], ...] = (
    ("anthropic", "anthropic"),
    ("bleach", "bleach"),
    ("opentelemetry-api", "opentelemetry"),
    ("opentelemetry-sdk", "opentelemetry"),
    ("gradio", "gradio"),
    ("httpx", "httpx"),
    ("hydra-core", "hydra"),
    ("numpy", "numpy"),
    ("omegaconf", "omegaconf"),
    ("openai", "openai"),
    ("jsonschema", "jsonschema"),
    ("regex", "regex"),
    ("structlog", "structlog"),
)


def _import_check(distribution: str, module: str) -> None:
    try:
        importlib.import_module(module)
    except ImportError as exc:
        raise EvaluationContractError(
            "package gate failed: required package "
            f"{distribution!r} is not installed (cannot import {module!r})"
        ) from exc


def _run_package_gate(packages: Sequence[tuple[str, str]]) -> None:
    seen_modules: set[str] = set()
    for distribution, module in packages:
        if module in seen_modules:
            continue
        seen_modules.add(module)
        _import_check(distribution, module)


@lru_cache(maxsize=1)
def _assert_default_evaluation_package_gate() -> None:
    _run_package_gate(EVALUATION_REQUIRED_PACKAGES)


def assert_evaluation_package_gate(
    packages: Sequence[tuple[str, str]] | None = None,
) -> None:
    """
    Verify that all evaluation runtime dependencies are importable.

    Raises EvaluationContractError on the first missing package (fail-closed).
    The default package list is cached per process.
    """
    if packages is None:
        _assert_default_evaluation_package_gate()
    else:
        _run_package_gate(packages)


def reset_evaluation_package_gate_cache() -> None:
    """Clear the package-gate cache (for tests)."""
    _assert_default_evaluation_package_gate.cache_clear()
