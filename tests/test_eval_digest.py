"""Tests for dataset digest and manifest generation (digest.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from src.eval.contract import (
    EvaluationContractError,
    compute_dataset_digest,
    evaluation_manifest_schema,
    load_dataset_manifest,
    validate_dataset_against_manifest,
)
from src.eval.digest import (
    build_dataset_manifest,
    compute_config_digest,
    compute_dataset_file_digest,
    compute_simulation_seed_digest,
    compute_sorted_jsonl_content_digest,
)
from src.eval.metadata import (
    RunContext,
    build_run_metadata,
    compute_config_fingerprint_sha256,
    frozen_metric_definitions,
)
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"
FROZEN_BASELINE_DIGEST = (
    "99a6515f3488f25e4ebaaf44880b42779b5671bd0045d92f793d37b475baded9"
)


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.write_text(
        "\n".join(json.dumps(row, sort_keys=True) for row in rows) + "\n",
        encoding="utf-8",
    )


def test_dataset_file_digest_is_deterministic() -> None:
    first = compute_dataset_file_digest(BASELINE_JSONL)
    second = compute_dataset_digest(BASELINE_JSONL)
    assert first == second == FROZEN_BASELINE_DIGEST


def test_sorted_jsonl_content_digest_is_deterministic() -> None:
    a = compute_sorted_jsonl_content_digest(BASELINE_JSONL)
    b = compute_sorted_jsonl_content_digest(BASELINE_JSONL)
    assert a == b
    assert len(a) == 64


def test_different_dataset_bytes_yield_different_file_digests(tmp_path: Path) -> None:
    path_a = tmp_path / "a.jsonl"
    path_b = tmp_path / "b.jsonl"
    row = {
        "case_id": "only",
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
        "case_type": "benign",
        "attack_family": "clean",
    }
    _write_jsonl(path_a, [row])
    _write_jsonl(path_b, [{**row, "prompt": "p2"}])
    assert compute_dataset_file_digest(path_a) != compute_dataset_file_digest(path_b)


def test_reordered_rows_change_sorted_content_digest_not_necessarily_file_digest(
    tmp_path: Path,
) -> None:
    rows = [
        {
            "case_id": "a",
            "prompt": "1",
            "context": "",
            "task_type": "chat",
            "expected_blocked": False,
        },
        {
            "case_id": "b",
            "prompt": "2",
            "context": "",
            "task_type": "chat",
            "expected_blocked": True,
        },
    ]
    ordered = tmp_path / "ordered.jsonl"
    reversed_path = tmp_path / "reversed.jsonl"
    _write_jsonl(ordered, rows)
    _write_jsonl(reversed_path, list(reversed(rows)))
    assert compute_sorted_jsonl_content_digest(ordered) == compute_sorted_jsonl_content_digest(
        reversed_path
    )
    assert compute_dataset_file_digest(ordered) != compute_dataset_file_digest(reversed_path)


def test_build_dataset_manifest_matches_committed_baseline() -> None:
    generated = build_dataset_manifest(
        BASELINE_JSONL,
        suite_name="baseline",
        packaged_resource="datasets/baseline.jsonl",
    )
    committed = load_dataset_manifest(BASELINE_MANIFEST)
    assert generated == committed


def test_build_dataset_manifest_validates_against_schema() -> None:
    manifest = build_dataset_manifest(BASELINE_JSONL, suite_name="baseline")
    validator = Draft202012Validator(evaluation_manifest_schema())
    errors = sorted(validator.iter_errors(manifest), key=lambda err: list(err.path))
    assert not errors
    validate_dataset_against_manifest(BASELINE_JSONL, manifest)


def test_run_metadata_includes_dataset_code_config_seed_and_metrics() -> None:
    context = RunContext.for_dataset(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
        code_commit_sha="b" * 40,
        config_fingerprint_sha256=compute_config_fingerprint_sha256(),
        metric_definitions=frozen_metric_definitions(),
    )
    metadata = build_run_metadata(context)
    assert metadata["dataset"]["content_digest_sha256"] == FROZEN_BASELINE_DIGEST
    assert metadata["code"]["commit_sha"] == "b" * 40
    assert metadata["code"]["config_fingerprint_sha256"] == compute_config_fingerprint_sha256()
    assert metadata["runtime"]["simulation_seed"] is None
    assert metadata["metrics"]["definitions"] == frozen_metric_definitions()
    assert len(compute_simulation_seed_digest(None)) == 64


def test_compute_config_digest_is_order_independent() -> None:
    assert compute_config_digest({"z": 1, "a": 2}) == compute_config_digest({"a": 2, "z": 1})


def test_simulation_seed_digest_rejects_non_null() -> None:
    with pytest.raises(EvaluationContractError, match="simulation_seed"):
        compute_simulation_seed_digest(object())  # type: ignore[arg-type]
