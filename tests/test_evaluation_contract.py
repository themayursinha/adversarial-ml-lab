"""Tests for frozen evaluation dataset/run contract (P1)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval.contract import (
    EvaluationContractError,
    baseline_manifest_path,
    build_run_provenance,
    compute_dataset_digest,
    load_dataset_manifest,
    metric_definitions,
    validate_dataset_against_manifest,
    validate_evaluation_row,
)
from src.services.evaluator import load_evaluation_cases, run_evaluation_suite
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"
PACKAGED_JSONL = REPO_ROOT / "src/resources/datasets/baseline.jsonl"
PACKAGED_MANIFEST = REPO_ROOT / "src/resources/datasets/baseline.manifest.json"


def test_baseline_manifest_matches_dataset_bytes() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    digest = compute_dataset_digest(BASELINE_JSONL)
    assert manifest["content_digest_sha256"] == digest
    assert manifest["case_count"] == 50
    assert len(manifest["case_ids"]) == 50
    assert len(set(manifest["case_ids"])) == 50


def test_packaged_baseline_matches_repo_manifest() -> None:
    repo = load_dataset_manifest(BASELINE_MANIFEST)
    packaged = load_dataset_manifest(PACKAGED_MANIFEST)
    assert repo == packaged
    assert PACKAGED_JSONL.read_bytes() == BASELINE_JSONL.read_bytes()


def test_validate_dataset_against_manifest_accepts_baseline() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    validate_dataset_against_manifest(BASELINE_JSONL, manifest)


def test_validate_evaluation_row_rejects_missing_case_id() -> None:
    with pytest.raises(EvaluationContractError, match="case_id"):
        validate_evaluation_row({"prompt": "x", "context": "", "task_type": "chat", "expected_blocked": False}, 1)


def test_validate_evaluation_row_rejects_duplicate_ids_in_file(tmp_path: Path) -> None:
    path = tmp_path / "dup.jsonl"
    rows = [
        {"case_id": "a", "prompt": "p", "context": "", "task_type": "chat", "expected_blocked": False},
        {"case_id": "a", "prompt": "p2", "context": "", "task_type": "chat", "expected_blocked": True},
    ]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    manifest = {
        "manifest_version": "1.0.0",
        "contract_id": "adml.evaluation.dataset.v1",
        "schema_ref": "evaluation_case.v1",
        "suite_name": "test",
        "dataset_filename": "dup.jsonl",
        "content_digest_sha256": compute_dataset_digest(path),
        "case_count": 2,
        "case_ids": ["a", "b"],
        "family_counts": {"unknown": 2},
        "required_fields": ["case_id", "prompt", "context", "task_type", "expected_blocked"],
        "allowed_case_types": ["benign", "adversarial"],
        "allowed_risk_levels": ["low", "medium", "high", "critical"],
    }
    with pytest.raises(EvaluationContractError, match="duplicate"):
        validate_dataset_against_manifest(path, manifest)


def test_load_evaluation_cases_fails_closed_on_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"case_id":"x"}\n', encoding="utf-8")
    with pytest.raises(EvaluationContractError):
        load_evaluation_cases(path)


def test_run_evaluation_suite_includes_provenance_and_metric_definitions() -> None:
    result = run_evaluation_suite(dataset_path=BASELINE_JSONL, suite_name="baseline")
    payload = result.to_dict(include_case_results=False)
    assert "provenance" in payload
    prov = payload["provenance"]
    assert prov["contract_id"] == "adml.evaluation.run.v1"
    assert prov["dataset"]["content_digest_sha256"] == compute_dataset_digest(BASELINE_JSONL)
    assert prov["runtime"]["llm_mode"] == LLMMode.SIMULATION.value
    assert prov["metrics"]["definitions"] == metric_definitions()
    assert "package_version" in prov["code"]


def test_baseline_metrics_unchanged_under_contract() -> None:
    result = run_evaluation_suite(dataset_path=BASELINE_JSONL, suite_name="baseline")
    assert result.total_cases == 50
    assert result.pass_rate == 0.92
    assert result.review_match_rate == pytest.approx(0.94)
    assert result.risk_match_rate == pytest.approx(0.82)


def test_baseline_manifest_path_resolves_for_packaged_resource() -> None:
    path = baseline_manifest_path(BASELINE_JSONL)
    assert path == BASELINE_MANIFEST


def test_build_run_provenance_is_deterministic() -> None:
    a = build_run_provenance(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    b = build_run_provenance(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    assert a == b


def _minimal_valid_row(case_id: str = "case_one") -> dict:
    return {
        "case_id": case_id,
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
    }


def _manifest_for(dataset: Path, *, case_count: int | bool = 1) -> dict:
    return {
        "manifest_version": "1.0.0",
        "contract_id": "adml.evaluation.dataset.v1",
        "suite_name": "custom",
        "dataset_filename": dataset.name,
        "content_digest_sha256": compute_dataset_digest(dataset),
        "case_count": case_count,
        "case_ids": ["case_one"],
        "family_counts": {"unknown": case_count},
        "schema_ref": "evaluation_case.v1",
        "required_fields": [
            "case_id",
            "prompt",
            "context",
            "task_type",
            "expected_blocked",
        ],
        "allowed_case_types": ["benign", "adversarial"],
        "allowed_risk_levels": ["low", "medium", "high", "critical"],
    }


def test_load_evaluation_cases_rejects_duplicate_ids_without_manifest(tmp_path: Path) -> None:
    path = tmp_path / "custom.jsonl"
    rows = [_minimal_valid_row("case_one"), _minimal_valid_row("case_one")]
    path.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="duplicate"):
        load_evaluation_cases(path)


def test_load_evaluation_cases_rejects_invalid_optional_field_types(tmp_path: Path) -> None:
    path = tmp_path / "bad_types.jsonl"
    row = {
        **_minimal_valid_row(),
        "case_type": 123,
        "attack_family": [],
        "notes": 7,
    }
    path.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError):
        load_evaluation_cases(path)


def test_empty_sibling_manifest_is_rejected(tmp_path: Path) -> None:
    dataset = tmp_path / "governed.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    (tmp_path / "governed.manifest.json").write_text("{}", encoding="utf-8")
    with pytest.raises(EvaluationContractError):
        load_evaluation_cases(dataset)


def test_load_evaluation_cases_rejects_boolean_manifest_counts(tmp_path: Path) -> None:
    dataset = tmp_path / "boolean_counts.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    manifest = _manifest_for(dataset, case_count=True)
    dataset.with_name("boolean_counts.manifest.json").write_text(
        json.dumps(manifest),
        encoding="utf-8",
    )

    with pytest.raises(EvaluationContractError, match="schema violation"):
        load_evaluation_cases(dataset)


def test_sibling_manifest_invalid_json_rejected(tmp_path: Path) -> None:
    dataset = tmp_path / "governed.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    (tmp_path / "governed.manifest.json").write_text("{not json", encoding="utf-8")
    with pytest.raises(EvaluationContractError):
        load_evaluation_cases(dataset)


def test_manifest_metadata_tampering_rejected(tmp_path: Path) -> None:
    dataset = tmp_path / "tamper.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    manifest = {
        "manifest_version": "1.0.0",
        "contract_id": "adml.evaluation.dataset.v1",
        "suite_name": "tamper",
        "dataset_filename": "wrong.jsonl",
        "content_digest_sha256": "0" * 64,
        "case_count": 99,
        "case_ids": ["other"],
        "family_counts": {"clean": 1},
        "required_fields": ["case_id"],
        "allowed_case_types": ["benign"],
        "allowed_risk_levels": ["low"],
    }
    (tmp_path / "tamper.manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(EvaluationContractError):
        load_evaluation_cases(dataset)


def test_run_provenance_ignores_absolute_path(tmp_path: Path) -> None:
    row = _minimal_valid_row()
    content = json.dumps(row) + "\n"
    path_a = tmp_path / "a" / "suite.jsonl"
    path_b = tmp_path / "b" / "suite.jsonl"
    path_a.parent.mkdir(parents=True)
    path_b.parent.mkdir(parents=True)
    path_a.write_text(content, encoding="utf-8")
    path_b.write_text(content, encoding="utf-8")
    prov_a = build_run_provenance(
        dataset_path=path_a,
        suite_name="custom",
        llm_mode=LLMMode.SIMULATION,
        manifest=None,
    )
    prov_b = build_run_provenance(
        dataset_path=path_b,
        suite_name="custom",
        llm_mode=LLMMode.SIMULATION,
        manifest=None,
    )
    assert prov_a == prov_b
    assert "path" not in prov_a["dataset"]


def test_build_run_provenance_rejects_invalid_explicit_manifest(tmp_path: Path) -> None:
    dataset = tmp_path / "custom.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    invalid_manifest = {
        "contract_id": "adml.evaluation.dataset.v1",
        "case_count": 999,
        "packaged_resource": "datasets/baseline.jsonl",
    }

    with pytest.raises(EvaluationContractError):
        build_run_provenance(
            dataset_path=dataset,
            suite_name="custom",
            llm_mode=LLMMode.SIMULATION,
            manifest=invalid_manifest,
        )


def test_build_run_provenance_rejects_empty_suite_name(tmp_path: Path) -> None:
    dataset = tmp_path / "custom.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")

    with pytest.raises(EvaluationContractError, match="suite_name"):
        build_run_provenance(
            dataset_path=dataset,
            suite_name="",
            llm_mode=LLMMode.SIMULATION,
        )


def test_schema_runtime_parity_rejects_schema_invalid_row() -> None:
    from src.eval.contract import validate_row_matches_evaluation_schema

    with pytest.raises(EvaluationContractError):
        validate_row_matches_evaluation_schema(
            {"case_id": "x", "prompt": 1, "context": "", "task_type": "t", "expected_blocked": False},
            1,
        )
