"""CLI smoke tests for the public command surface."""

from __future__ import annotations

import json
from argparse import Namespace

from src.cli import run_eval_command, run_scan_command


def test_run_scan_command_emits_json(capsys, tmp_path) -> None:
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Quarterly report with normal business metrics.", encoding="utf-8")

    exit_code = run_scan_command(
        Namespace(
            file=str(sample_file),
            prompt="Please summarize this document.",
            task="summarize",
            simulate_vulnerable=False,
        )
    )

    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["risk_level"] in {"low", "medium", "high", "critical"}
    assert "events" in payload
    assert isinstance(payload["blocked"], bool)


def test_run_eval_command_uses_packaged_dataset_by_default(capsys) -> None:
    exit_code = run_eval_command(Namespace(dataset=None, suite="baseline", show_cases=False))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["suite_name"] == "baseline"
    assert payload["total_cases"] == 24
    assert payload["review_match_rate"] == 1.0
    assert payload["risk_match_rate"] == 1.0
    assert payload["family_metrics"]["clean"]["total_cases"] == 6
    assert "case_results" not in payload


def test_run_eval_command_can_include_per_case_results(capsys) -> None:
    exit_code = run_eval_command(Namespace(dataset=None, suite="baseline", show_cases=True))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(payload["case_results"]) == payload["total_cases"]
    assert payload["case_results"][0]["case_id"]
    assert "matched_block_expectation" in payload["case_results"][0]
