"""Unit tests for the evaluation Python package gate."""

from __future__ import annotations

import importlib
from collections.abc import Iterator
from unittest.mock import patch

import pytest

from src.eval.contract import EvaluationContractError
from src.eval.package_gate import (
    EVALUATION_REQUIRED_PACKAGES,
    assert_evaluation_package_gate,
    reset_evaluation_package_gate_cache,
)


@pytest.fixture(autouse=True)
def _clear_package_gate_cache() -> Iterator[None]:
    reset_evaluation_package_gate_cache()
    yield
    reset_evaluation_package_gate_cache()


def test_evaluation_required_packages_includes_jsonschema() -> None:
    dists = {dist for dist, _ in EVALUATION_REQUIRED_PACKAGES}
    assert "jsonschema" in dists


def test_package_gate_passes_with_installed_runtime() -> None:
    assert_evaluation_package_gate()


def test_package_gate_fails_closed_on_missing_import() -> None:
    real_import = importlib.import_module

    def fake_import(name: str, package: str | None = None):
        if name == "missing_eval_pkg":
            raise ImportError("simulated missing package")
        return real_import(name, package)

    with patch("src.eval.package_gate.importlib.import_module", side_effect=fake_import):
        with pytest.raises(EvaluationContractError, match="package gate failed"):
            assert_evaluation_package_gate([("missing-eval", "missing_eval_pkg")])


def test_package_gate_deduplicates_shared_import_modules() -> None:
    calls: list[str] = []

    def recorder(name: str, package: str | None = None):
        calls.append(name)
        return real_import(name, package)

    real_import = importlib.import_module
    with patch("src.eval.package_gate.importlib.import_module", side_effect=recorder):
        assert_evaluation_package_gate(
            [
                ("opentelemetry-api", "opentelemetry"),
                ("opentelemetry-sdk", "opentelemetry"),
            ]
        )
    assert calls == ["opentelemetry"]
