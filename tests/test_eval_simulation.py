"""Tests for offline evaluation simulation (no LLM API)."""

from __future__ import annotations

import json
import socket
from argparse import Namespace
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from src.eval.contract import EvaluationContractError, evaluation_run_provenance_schema
from src.eval.simulate import run_simulate, run_simulate_command
from src.eval.simulation import (
    SIMULATION_PIPELINE_ID,
    run_simulation_evaluation,
    stable_simulation_snapshot,
    validate_simulation_report,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
EXAMPLE_REPORT = REPO_ROOT / "evals/examples/baseline_simulation_report.json"


def _block_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fail any outbound socket connection (simulation must stay offline)."""

    real_socket = socket.socket

    def guarded_socket(*args, **kwargs):
        sock = real_socket(*args, **kwargs)

        def blocked_connect(address):
            raise OSError(f"network blocked during simulation test: {address}")

        sock.connect = blocked_connect  # type: ignore[method-assign]
        return sock

    monkeypatch.setattr(socket, "socket", guarded_socket)


def test_run_simulation_evaluation_baseline_without_network(monkeypatch) -> None:
    _block_network(monkeypatch)
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-should-not-be-used")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-test-should-not-be-used")

    report = run_simulation_evaluation(BASELINE_JSONL, suite_name="baseline")

    assert report["simulation"] is True
    assert report["pipeline"] == SIMULATION_PIPELINE_ID
    assert report["suite_name"] == "baseline"
    assert report["total_cases"] == 50
    assert report["provenance"]["runtime"]["llm_mode"] == "simulation"
    assert report["provenance"]["runtime"]["deterministic"] is True
    validate_simulation_report(report)


def test_simulation_report_is_deterministic() -> None:
    a = run_simulation_evaluation(BASELINE_JSONL, suite_name="baseline")
    b = run_simulation_evaluation(BASELINE_JSONL, suite_name="baseline")
    assert stable_simulation_snapshot(a) == stable_simulation_snapshot(b)


def test_validate_simulation_report_rejects_missing_provenance() -> None:
    with pytest.raises(EvaluationContractError, match="provenance"):
        validate_simulation_report({"simulation": True, "pipeline": SIMULATION_PIPELINE_ID})


def test_provenance_in_report_matches_json_schema() -> None:
    report = run_simulation_evaluation(BASELINE_JSONL, suite_name="baseline")
    validator = Draft202012Validator(evaluation_run_provenance_schema())
    errors = sorted(validator.iter_errors(report["provenance"]), key=lambda e: list(e.path))
    assert errors == []


def test_run_simulate_command_default_baseline(capsys, monkeypatch) -> None:
    _block_network(monkeypatch)
    exit_code = run_simulate_command(
        Namespace(
            dataset=None,
            dataset_opt=None,
            suite=None,
            show_cases=False,
            no_packaged_parity=False,
            quiet=True,
        )
    )
    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["simulation"] is True
    assert payload["total_cases"] == 50


def test_packaged_example_report_matches_live_simulation() -> None:
    """Checked-in example stays in sync with the simulation pipeline."""
    assert EXAMPLE_REPORT.is_file(), "run scripts/generate_simulation_example.py"
    example = json.loads(EXAMPLE_REPORT.read_text(encoding="utf-8"))
    live = run_simulate(None, suite_name="baseline", include_case_results=False)
    assert stable_simulation_snapshot(example) == stable_simulation_snapshot(live)


def test_run_simulate_custom_dataset(tmp_path: Path) -> None:
    row = {
        "case_id": "sim_one",
        "prompt": "Summarize the quarterly report.",
        "context": "Revenue grew 12% year over year.",
        "task_type": "summarize",
        "expected_blocked": False,
        "case_type": "benign",
        "attack_family": "clean",
    }
    dataset = tmp_path / "mini.jsonl"
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    report = run_simulate(
        dataset,
        suite_name="mini",
        check_packaged_parity=False,
    )
    assert report["total_cases"] == 1
    assert report["provenance"]["dataset"]["case_count"] is None
