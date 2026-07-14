"""CLI smoke tests for the public command surface."""

from __future__ import annotations

import builtins
import json
from argparse import Namespace

from src.cli import (
    run_eval_command,
    run_image_attack_command,
    run_rag_command,
    run_scan_command,
)
from src.utils.logging import configure_silent


def _ns(**kwargs: object) -> Namespace:
    """Build a Namespace with logging defaults pre-populated."""
    defaults = {
        "mode": None,
        "log_level": "INFO",
        "json_logs": False,
        "quiet": False,
    }
    defaults.update(kwargs)
    return Namespace(**defaults)


def test_run_scan_command_emits_json(capsys, tmp_path) -> None:
    configure_silent()
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Quarterly report with normal business metrics.", encoding="utf-8")

    exit_code = run_scan_command(
        _ns(
            file=str(sample_file),
            prompt="Please summarize this document.",
            task="summarize",
            simulate_vulnerable=False,
            quiet=True,
        )
    )

    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["risk_level"] in {"low", "medium", "high", "critical"}
    assert "events" in payload
    assert isinstance(payload["blocked"], bool)
    assert payload["llm_mode"] == "simulation"
    assert "latency_ms" in payload
    assert "tokens_used" in payload


def test_run_eval_command_uses_packaged_dataset_by_default(capsys) -> None:
    configure_silent()
    exit_code = run_eval_command(_ns(dataset=None, suite="baseline", show_cases=False, quiet=True))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert payload["suite_name"] == "baseline"
    assert payload["total_cases"] == 50
    assert payload["review_match_rate"] is not None
    assert payload["risk_match_rate"] is not None
    assert payload["family_metrics"]["clean"]["total_cases"] == 13
    assert "case_results" not in payload


def test_run_eval_command_can_include_per_case_results(capsys) -> None:
    configure_silent()
    exit_code = run_eval_command(_ns(dataset=None, suite="baseline", show_cases=True, quiet=True))
    payload = json.loads(capsys.readouterr().out)

    assert exit_code == 0
    assert len(payload["case_results"]) == payload["total_cases"]
    assert payload["case_results"][0]["case_id"]
    assert "matched_block_expectation" in payload["case_results"][0]


def test_run_scan_command_has_mode_in_output(capsys, tmp_path) -> None:
    configure_silent()
    sample_file = tmp_path / "sample.txt"
    sample_file.write_text("Normal content.", encoding="utf-8")

    exit_code = run_scan_command(
        _ns(
            file=str(sample_file),
            prompt="Summarize.",
            task="summarize",
            simulate_vulnerable=False,
            mode="simulation",
            quiet=True,
        )
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["llm_mode"] == "simulation"
    assert "model" in payload


def test_image_attack_without_vision_extra_returns_actionable_error(monkeypatch, capsys) -> None:
    real_import = builtins.__import__

    def import_without_torch(name, *args, **kwargs):
        if name == "torch":
            raise ImportError("torch intentionally unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_torch)

    exit_code = run_image_attack_command(
        _ns(attack="fgsm", epsilon=0.03, steps=10, quiet=True)
    )

    assert exit_code == 1
    assert 'pip install "adversarial-ml-lab[vision]"' in capsys.readouterr().err


def test_rag_without_rag_extra_returns_actionable_error(monkeypatch, capsys) -> None:
    real_import = builtins.__import__

    def import_without_sentence_transformers(name, *args, **kwargs):
        if name == "sentence_transformers":
            raise ImportError("sentence-transformers intentionally unavailable")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_sentence_transformers)

    exit_code = run_rag_command(_ns(query="What is the refund window?", poison=False, quiet=True))

    assert exit_code == 1
    assert 'pip install "adversarial-ml-lab[rag]"' in capsys.readouterr().err
