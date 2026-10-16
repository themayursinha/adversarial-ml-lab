"""Regression gate tests (board t_8fd3d263).

Evidence covered: green baseline, intentional failing fixture, schema
conformance, deterministic reruns, case-diff tooling, and digest binding.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval.contract import EvaluationContractError, validate_json_document
from src.eval.regression import (
    RegressionGateError,
    diff_case_outcomes,
    load_regression_thresholds_schema,
    load_threshold_policy,
    run_regression_gate,
    wilson_interval,
    write_gate_artifacts,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
V2_JSONL = REPO_ROOT / "evals/datasets/baseline_v2.jsonl"
V2_THRESHOLDS = REPO_ROOT / "evals/thresholds/baseline_v2.thresholds.json"
V2_BASELINE_SNAPSHOT = REPO_ROOT / "evals/examples/baseline_v2_regression_baseline.json"
FIXTURE_DIR = REPO_ROOT / "evals/fixtures/regression_gate_fail"
FIXTURE_JSONL = FIXTURE_DIR / "dataset.jsonl"
FIXTURE_THRESHOLDS = FIXTURE_DIR / "thresholds.json"


def test_threshold_policy_conforms_to_schema() -> None:
    """The committed policy must match the packaged schema and bind the corpus."""
    policy = load_threshold_policy(V2_THRESHOLDS)
    assert policy["policy_id"] == "adml.regression.thresholds.baseline_v2"
    assert policy["dataset_filename"] == "baseline_v2.jsonl"
    assert set(policy["families"]) == {
        "clean",
        "context_tampering",
        "data_exfiltration",
        "inference_evasion",
        "jailbreak",
        "many_shot",
        "prompt_injection",
        "rag_poisoning",
        "tool_misuse",
    }


def test_green_baseline_gate_passes(tmp_path: Path) -> None:
    """The frozen corpus plus committed policy and snapshot must pass."""
    gate = run_regression_gate(
        V2_JSONL,
        V2_THRESHOLDS,
        V2_BASELINE_SNAPSHOT,
    )
    assert gate["decision"] == "PASS", gate["threshold_results"]["failures"]
    assert gate["case_diff"]["changed_count"] == 0

    artifacts = write_gate_artifacts(gate, tmp_path)
    assert [path.name for path in artifacts] == [
        "aggregate_metrics.json",
        "regression_gate.json",
        "case_diff.json",
        "regression_report.md",
    ]
    gate_doc = json.loads((tmp_path / "regression_gate.json").read_text(encoding="utf-8"))
    assert gate_doc["decision"] == "PASS"


def test_gate_artifacts_are_deterministic(tmp_path: Path) -> None:
    """Two independent runs must produce byte-identical artifacts."""
    gate_one = run_regression_gate(V2_JSONL, V2_THRESHOLDS, V2_BASELINE_SNAPSHOT)
    gate_two = run_regression_gate(V2_JSONL, V2_THRESHOLDS, V2_BASELINE_SNAPSHOT)
    assert gate_one == gate_two

    write_gate_artifacts(gate_one, tmp_path / "one")
    write_gate_artifacts(gate_two, tmp_path / "two")
    for name in (
        "aggregate_metrics.json",
        "regression_gate.json",
        "case_diff.json",
        "regression_report.md",
    ):
        assert (tmp_path / "one" / name).read_bytes() == (tmp_path / "two" / name).read_bytes()


def test_intentional_failing_fixture_fails(tmp_path: Path) -> None:
    """The fixture policy is unreachable by construction and must FAIL."""
    gate = run_regression_gate(FIXTURE_JSONL, FIXTURE_THRESHOLDS, None)
    assert gate["decision"] == "FAIL"
    failures = gate["threshold_results"]["failures"]
    assert "global.adversarial_miss_rate" in failures
    assert "global.pass_rate" in failures

    write_gate_artifacts(gate, tmp_path)
    gate_doc = json.loads((tmp_path / "regression_gate.json").read_text(encoding="utf-8"))
    assert gate_doc["decision"] == "FAIL"


def test_policy_rejects_other_dataset() -> None:
    """A policy pinned to baseline_v2 must fail closed against the legacy corpus."""
    with pytest.raises(RegressionGateError, match="different dataset digest"):
        run_regression_gate(
            REPO_ROOT / "evals/datasets/baseline.jsonl",
            V2_THRESHOLDS,
            None,
        )


def test_baseline_snapshot_digest_binding(tmp_path: Path) -> None:
    """A tampered snapshot digest must fail closed, not silently pass the diff."""
    snapshot = json.loads(V2_BASELINE_SNAPSHOT.read_text(encoding="utf-8"))
    snapshot["dataset_digest_sha256"] = "0" * 64
    tampered = tmp_path / "tampered_baseline.json"
    tampered.write_text(json.dumps(snapshot), encoding="utf-8")
    with pytest.raises(RegressionGateError, match="baseline snapshot digest"):
        run_regression_gate(V2_JSONL, V2_THRESHOLDS, tampered)


def test_case_diff_identifies_changed_outcomes() -> None:
    """The case-diff must pinpoint the case whose outcome drifted."""
    baseline = {
        "case_a": {"blocked": False, "needs_human_review": False, "risk_level": "low",
                   "matched_block_expectation": True},
        "case_b": {"blocked": True, "needs_human_review": False, "risk_level": "high",
                   "matched_block_expectation": True},
    }
    current = {
        "case_a": {"blocked": True, "needs_human_review": False, "risk_level": "low",
                   "matched_block_expectation": True},
        "case_b": {"blocked": True, "needs_human_review": False, "risk_level": "high",
                   "matched_block_expectation": True},
        "case_c": {"blocked": False, "needs_human_review": False, "risk_level": "low",
                   "matched_block_expectation": True},
    }
    diff = diff_case_outcomes(baseline, current)
    assert diff["changed_count"] == 2
    assert set(diff["changed"]) == {"case_a"}
    assert diff["added"] == ["case_c"]
    assert diff["removed"] == []


def test_baseline_snapshot_covers_full_corpus() -> None:
    """The committed snapshot must document every case outcome once."""
    snapshot = json.loads(V2_BASELINE_SNAPSHOT.read_text(encoding="utf-8"))
    assert snapshot["case_count"] == 204
    assert len(snapshot["case_outcomes"]) == 204
    for outcome in snapshot["case_outcomes"].values():
        assert set(outcome) == {
            "blocked",
            "needs_human_review",
            "risk_level",
            "matched_block_expectation",
        }


def test_wilson_interval_math() -> None:
    """Closed-form bounds must behave at the extremes and bracket the point."""
    low, high = wilson_interval(0, 10, 3.0)
    assert low < 0.01
    assert 0.0 < high < 0.75
    low, high = wilson_interval(10, 10, 3.0)
    assert high == 1.0
    assert 0.5 < low < 1.0
    low, high = wilson_interval(50, 100, 3.0)
    assert low < 0.5 < high
    with pytest.raises(RegressionGateError):
        wilson_interval(1, 0, 3.0)


def test_fixture_thresholds_match_fixture_bytes() -> None:
    """The fixture policy must stay pinned to the fixture dataset bytes."""
    import hashlib

    policy = load_threshold_policy(FIXTURE_THRESHOLDS)
    digest = hashlib.sha256(FIXTURE_JSONL.read_bytes()).hexdigest()
    assert policy["dataset_digest_sha256"] == digest


def test_malformed_policy_fails_closed(tmp_path: Path) -> None:
    """Unknown policy fields must be rejected by the packaged schema."""
    bad = json.loads(V2_THRESHOLDS.read_text(encoding="utf-8"))
    bad["unexpected_field"] = True
    bad_path = tmp_path / "bad_policy.json"
    bad_path.write_text(json.dumps(bad), encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="schema violation"):
        load_threshold_policy(bad_path)


def test_packaged_schema_loads() -> None:
    """The packaged thresholds schema must accept valid and reject invalid docs."""
    schema = load_regression_thresholds_schema()
    validate_json_document(
        {
            "schema_version": "1.0.0",
            "policy_id": "adml.regression.thresholds.probe",
            "policy_version": "1.0.0",
            "dataset_filename": "x.jsonl",
            "dataset_digest_sha256": "a" * 64,
            "z": 3.0,
            "metrics": {
                "pass_rate": {
                    "direction": "max",
                    "threshold": 0.5,
                    "margin": 0.1,
                    "baseline": 0.6,
                    "justification": "probe",
                }
            },
            "families": {},
            "reviewed_by": "probe",
            "reviewed_utc": "2026-09-14T00:00:00Z",
        },
        schema,
        label="probe",
    )
    with pytest.raises(EvaluationContractError):
        validate_json_document({"schema_version": "9.9.9"}, schema, label="probe")
