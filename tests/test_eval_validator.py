"""Tests for src.eval.validator public API."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.eval.contract import (
    CONTRACT_DATASET_V1,
    MANIFEST_VERSION,
    EvaluationContractError,
    compute_dataset_digest,
    load_dataset_manifest,
    metric_definitions,
)
from src.eval.validator import generate_run_metadata, validate_dataset
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"


def _minimal_valid_row(
    case_id: str = "case_one",
    *,
    attack_family: str = "clean",
    case_type: str = "benign",
) -> dict:
    return {
        "case_id": case_id,
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
        "case_type": case_type,
        "attack_family": attack_family,
    }


def _governed_manifest(
    dataset_path: Path,
    case_ids: list[str],
    family_counts: dict[str, int],
    *,
    required_fields: list[str] | None = None,
) -> dict:
    return {
        "manifest_version": MANIFEST_VERSION,
        "contract_id": CONTRACT_DATASET_V1,
        "suite_name": "test_suite",
        "dataset_filename": dataset_path.name,
        "content_digest_sha256": compute_dataset_digest(dataset_path),
        "case_count": len(case_ids),
        "case_ids": case_ids,
        "family_counts": family_counts,
        "schema_ref": "evaluation_case.v1",
        "required_fields": required_fields
        or [
            "case_id",
            "prompt",
            "context",
            "task_type",
            "expected_blocked",
            "case_type",
            "attack_family",
        ],
        "allowed_case_types": ["benign", "adversarial"],
        "allowed_risk_levels": ["low", "medium", "high", "critical"],
    }


def test_validate_dataset_accepts_baseline_with_manifest() -> None:
    manifest = validate_dataset(BASELINE_JSONL)
    assert manifest is not None
    assert manifest["case_count"] == 50


def test_validate_dataset_accepts_explicit_manifest() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    validate_dataset(BASELINE_JSONL, manifest)


def test_validate_dataset_accepts_ungoverned_valid_rows(tmp_path: Path) -> None:
    path = tmp_path / "solo.jsonl"
    path.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    assert validate_dataset(path) is None


def test_validate_dataset_rejects_manifest_schema_violation(tmp_path: Path) -> None:
    dataset = tmp_path / "one.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "case_id": "only",
                "prompt": "p",
                "context": "",
                "task_type": "chat",
                "expected_blocked": False,
            }
        )
        + "\n",
        encoding="utf-8",
    )
    bad_manifest = {
        "manifest_version": "9.9.9",
        "contract_id": "adml.evaluation.dataset.v1",
        "suite_name": "x",
        "dataset_filename": "one.jsonl",
        "content_digest_sha256": compute_dataset_digest(dataset),
        "case_count": 1,
        "case_ids": ["only"],
        "family_counts": {"unknown": 1},
        "schema_ref": "evaluation_case.v1",
        "required_fields": ["case_id"],
        "allowed_case_types": ["benign"],
        "allowed_risk_levels": ["low"],
    }
    with pytest.raises(EvaluationContractError, match="schema violation"):
        validate_dataset(dataset, bad_manifest)


def test_validate_dataset_rejects_packaged_parity_violation(tmp_path: Path) -> None:
    dataset = tmp_path / "baseline.jsonl"
    lines = BASELINE_JSONL.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[0])
    row["notes"] = (row.get("notes") or "") + " tamper"
    lines[0] = json.dumps(row, ensure_ascii=False)
    dataset.write_text("\n".join(lines) + "\n", encoding="utf-8")
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    manifest = dict(manifest)
    manifest["content_digest_sha256"] = compute_dataset_digest(dataset)
    manifest["dataset_filename"] = "baseline.jsonl"
    with pytest.raises(EvaluationContractError, match="parity"):
        validate_dataset(dataset, manifest)


def test_validate_dataset_rejects_packaged_resource_path_traversal() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    manifest["packaged_resource"] = "../datasets/baseline.jsonl"

    with pytest.raises(EvaluationContractError, match="schema violation"):
        validate_dataset(BASELINE_JSONL, manifest)


def test_validate_dataset_rejects_digest_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "one.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["case_one"], {"clean": 1})
    manifest["content_digest_sha256"] = "a" * 64
    with pytest.raises(EvaluationContractError, match="digest mismatch"):
        validate_dataset(dataset, manifest)


def test_validate_dataset_rejects_duplicate_case_ids(tmp_path: Path) -> None:
    dataset = tmp_path / "dup.jsonl"
    rows = [_minimal_valid_row("dup_id"), _minimal_valid_row("dup_id")]
    dataset.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["dup_id", "other_id"], {"clean": 2})
    with pytest.raises(EvaluationContractError, match="duplicate"):
        validate_dataset(dataset, manifest)


def test_validate_dataset_rejects_duplicate_case_ids_without_manifest(tmp_path: Path) -> None:
    dataset = tmp_path / "dup.jsonl"
    rows = [_minimal_valid_row("dup_id"), _minimal_valid_row("dup_id")]
    dataset.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="duplicate"):
        validate_dataset(dataset)


def test_validate_dataset_rejects_missing_manifest_required_field(tmp_path: Path) -> None:
    dataset = tmp_path / "missing.jsonl"
    row = _minimal_valid_row()
    del row["attack_family"]
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["case_one"], {"unknown": 1})
    with pytest.raises(EvaluationContractError, match="requires field 'attack_family'"):
        validate_dataset(dataset, manifest)


def test_validate_dataset_rejects_missing_core_schema_field(tmp_path: Path) -> None:
    dataset = tmp_path / "missing.jsonl"
    row = _minimal_valid_row()
    del row["prompt"]
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="schema violation"):
        validate_dataset(dataset)


def test_validate_dataset_rejects_invalid_case_type(tmp_path: Path) -> None:
    dataset = tmp_path / "bad_type.jsonl"
    row = _minimal_valid_row(case_type="not_a_type")
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["case_one"], {"clean": 1})
    with pytest.raises(EvaluationContractError, match="not_a_type"):
        validate_dataset(dataset, manifest)


def test_validate_dataset_rejects_family_counts_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "families.jsonl"
    row = _minimal_valid_row(attack_family="prompt_injection")
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["case_one"], {"clean": 1})
    with pytest.raises(EvaluationContractError, match="family_counts mismatch"):
        validate_dataset(dataset, manifest)


def test_validate_dataset_rejects_malformed_json(tmp_path: Path) -> None:
    dataset = tmp_path / "bad.jsonl"
    dataset.write_text("{not json\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="invalid JSON"):
        validate_dataset(dataset)


def test_validate_dataset_rejects_empty_line(tmp_path: Path) -> None:
    dataset = tmp_path / "blank.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="empty line"):
        validate_dataset(dataset)


def test_validate_dataset_rejects_empty_dataset(tmp_path: Path) -> None:
    dataset = tmp_path / "empty.jsonl"
    dataset.write_text("", encoding="utf-8")

    with pytest.raises(EvaluationContractError, match="at least one"):
        validate_dataset(dataset)


def test_validate_dataset_rejects_invalid_case_id_pattern(tmp_path: Path) -> None:
    dataset = tmp_path / "bad_id.jsonl"
    row = _minimal_valid_row(case_id="INVALID-ID")
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="schema violation"):
        validate_dataset(dataset)


def test_validate_dataset_rejects_case_id_ordering_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "order.jsonl"
    rows = [_minimal_valid_row("a"), _minimal_valid_row("b")]
    dataset.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["b", "a"], {"clean": 2})
    with pytest.raises(EvaluationContractError, match="ordering"):
        validate_dataset(dataset, manifest)


def test_generate_run_metadata_simulation_without_api() -> None:
    meta = generate_run_metadata(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    assert meta["contract_id"] == "adml.evaluation.run.v1"
    assert meta["runtime"]["llm_mode"] == "simulation"
    assert meta["runtime"]["simulation_seed"] is None
    assert meta["runtime"]["deterministic"] is True
    assert meta["metrics"]["definitions"]
    assert meta["code"]["config_fingerprint_sha256"]
    assert meta["dataset"]["content_digest_sha256"] == compute_dataset_digest(BASELINE_JSONL)


def test_generate_run_metadata_includes_frozen_metric_definitions() -> None:
    meta = generate_run_metadata(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    assert meta["metrics"]["definitions"] == metric_definitions()


def test_generate_run_metadata_is_deterministic() -> None:
    a = generate_run_metadata(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    b = generate_run_metadata(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    assert a == b


def test_generate_run_metadata_with_explicit_manifest(tmp_path: Path) -> None:
    dataset = tmp_path / "custom.jsonl"
    dataset.write_text(json.dumps(_minimal_valid_row()) + "\n", encoding="utf-8")
    manifest = _governed_manifest(dataset, ["case_one"], {"clean": 1})
    validate_dataset(dataset, manifest)
    meta = generate_run_metadata(
        dataset_path=dataset,
        suite_name="test_suite",
        llm_mode=LLMMode.SIMULATION,
        manifest=manifest,
    )
    assert meta["dataset"]["case_count"] == 1
    assert meta["dataset"]["content_digest_sha256"] == compute_dataset_digest(dataset)
