"""Defense ablation harness tests (board t_145d47d5)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval.ablation import (
    ABLATION_CONFIGS,
    AblationError,
    confusion_matrix,
    run_ablation,
)
from src.services.defense_pipeline import DefensePipeline
from src.services.evaluator import load_evaluation_cases

REPO_ROOT = Path(__file__).resolve().parents[1]
V2_JSONL = REPO_ROOT / "evals/datasets/baseline_v2.jsonl"
COMMITTED_REPORT = REPO_ROOT / "evals/examples/baseline_v2_ablation_report.json"

EXPECTED_CONFIGS = {
    "defense_off",
    "canonicalization_only",
    "filter_only",
    "anomaly_only",
    "uncertainty_only",
    "isolation_only",
    "redaction_only",
    "canonicalization_plus_filter",
    "default_pipeline",
    "all_controls",
}


def test_all_six_controls_measured_alone() -> None:
    """Every named control has a single-control config in the grid."""
    assert set(ABLATION_CONFIGS) == EXPECTED_CONFIGS
    alone = {
        "canonicalization_only": "canonicalization",
        "filter_only": "context_filter",
        "anomaly_only": "anomaly",
        "uncertainty_only": "uncertainty",
        "isolation_only": "isolation",
        "redaction_only": "redaction",
    }
    for config_name, control in alone.items():
        config = ABLATION_CONFIGS[config_name]
        flags = {
            config.canonicalization,
            config.context_filter,
            config.anomaly,
            config.uncertainty,
            config.isolation,
            config.redaction,
        }
        assert flags == {False, True}, config_name
        assert getattr(config, control) is True


@pytest.fixture(scope="module")
def report() -> dict:
    """Recompute the ablation report for the governed corpus."""
    return run_ablation(V2_JSONL)


def test_report_is_deterministic(report: dict) -> None:
    """Two runs must be identical; the committed artifact must match."""
    assert run_ablation(V2_JSONL) == report
    committed = json.loads(COMMITTED_REPORT.read_text(encoding="utf-8"))
    assert report == committed


def test_default_pipeline_matches_production_pipeline(report: dict) -> None:
    """The harness default config must reproduce production DefensePipeline outcomes."""
    default = report["configs"]["default_pipeline"]["blocked_confusion_matrix"]
    cases = load_evaluation_cases(V2_JSONL)
    client_blocked = 0
    client_review = 0
    client = __import__("src.utils.llm_client", fromlist=["LLMClient"]).LLMClient(
        mode=__import__("src.utils.llm_client", fromlist=["LLMMode"]).LLMMode.SIMULATION
    )
    pipeline = DefensePipeline()
    for case in cases:
        response = client.generate(
            prompt=case.prompt,
            context=case.context,
            task_type=case.task_type,
            simulate_vulnerable=True,
        )
        result = pipeline.analyze_output(
            input_text=f"{case.context} {case.prompt}",
            output_text=response.content,
            expected_task=case.task_type,
        )
        client_blocked += 1 if result.detection.blocked else 0
        client_review += 1 if result.needs_human_review else 0
    assert default["true_positives"] + default["false_positives"] == client_blocked
    assert report["configs"]["default_pipeline"]["flagged_confusion_matrix"][
        "true_positives"
    ] + report["configs"]["default_pipeline"]["flagged_confusion_matrix"][
        "false_positives"
    ] >= client_review


def test_only_blocking_controls_block(report: dict) -> None:
    """Alert-only controls must never block; filter-bearing configs must block."""
    for name in ("anomaly_only", "uncertainty_only", "canonicalization_only",
                 "isolation_only", "redaction_only", "defense_off"):
        matrix = report["configs"][name]["blocked_confusion_matrix"]
        assert matrix["true_positives"] + matrix["false_positives"] == 0, name
    for name in ("filter_only", "default_pipeline", "all_controls"):
        matrix = report["configs"][name]["blocked_confusion_matrix"]
        assert matrix["true_positives"] + matrix["false_positives"] > 0, name


def test_canonicalization_and_combos_add_no_marginal_blocking(report: dict) -> None:
    """Documented finding: on this corpus only the filter blocks; preprocessing and
    telemetry controls add zero marginal blocked detections. If a defense change
    alters this, the report and this test must be updated together."""
    filter_only = report["configs"]["filter_only"]["blocked_confusion_matrix"]
    for name in ("canonicalization_plus_filter", "default_pipeline", "all_controls"):
        assert report["configs"][name]["blocked_confusion_matrix"] == filter_only, name


def test_isolation_yields_no_single_turn_detections(report: dict) -> None:
    """Isolation needs session state; single-turn corpus cases get no signal."""
    matrix = report["configs"]["isolation_only"]["flagged_confusion_matrix"]
    assert matrix["true_positives"] == 0


def test_failures_are_risk_ranked(report: dict) -> None:
    """Miss lists must be ordered by descending expected risk."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    failures = report["configs"]["default_pipeline"]["failures"]["misses"]
    assert failures, "default pipeline must have documented misses on this corpus"
    ranks = [order.get(entry["expected_risk_level"], 4) for entry in failures]
    assert ranks == sorted(ranks)
    assert report["configs"]["default_pipeline"]["failures"]["risk_counts"]["misses"].get(
        "critical", 0
    ) > 0


def test_disclaimer_present(report: dict) -> None:
    """The report must carry the no-production-efficacy disclaimer."""
    assert "not production-efficacy claims" in report["disclaimer"]


def test_confusion_matrix_math() -> None:
    """Ground-truth matrix decomposition on a synthetic outcome set."""
    outcomes = [
        {"case_type": "adversarial", "expected_blocked": True, "blocked": True,
         "flagged": True},
        {"case_type": "adversarial", "expected_blocked": True, "blocked": False,
         "flagged": False},
        {"case_type": "benign", "expected_blocked": False, "blocked": False,
         "flagged": False},
        {"case_type": "benign", "expected_blocked": False, "blocked": True,
         "flagged": True},
        {"case_type": "adversarial", "expected_blocked": False, "blocked": True,
         "flagged": True},
    ]
    blocked = confusion_matrix(outcomes, "blocked")
    assert blocked == {
        "true_positives": 1,
        "false_positives": 1,
        "false_negatives": 1,
        "true_negatives": 1,
        "neutralize_total": 1,
        "neutralize_flagged": 1,
    }


def test_unknown_config_fails_closed() -> None:
    """Unknown config names must be rejected."""
    with pytest.raises(AblationError, match="unknown ablation configs"):
        run_ablation(V2_JSONL, config_names=["no_such_config"])
