"""Validation and reproducibility acceptance tests for the evaluation contract.

Maps to P1 acceptance: unique IDs, required field labels, families, parity,
ordering, fail-closed behavior, and digest consistency (frozen baseline).
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib.resources import as_file, files
from pathlib import Path

import pytest

from src.eval.contract import (
    CONTRACT_DATASET_V1,
    EvaluationContractError,
    compute_dataset_digest,
    load_dataset_manifest,
    resolve_dataset_manifest,
    validate_dataset_against_manifest,
    validate_evaluation_row,
    validate_manifest_document,
)
from src.eval.validator import validate_dataset

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"

# Frozen at P1 — must match evals/datasets/baseline.manifest.json
FROZEN_BASELINE_DIGEST_SHA256 = (
    "99a6515f3488f25e4ebaaf44880b42779b5671bd0045d92f793d37b475baded9"
)


def _minimal_row(**overrides: object) -> dict:
    base = {
        "case_id": "case_one",
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
        "case_type": "benign",
        "attack_family": "clean",
    }
    base.update(overrides)
    return base


# --- digest reproducibility ---


def test_frozen_baseline_digest_matches_manifest_and_file() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    digest = compute_dataset_digest(BASELINE_JSONL)
    assert manifest["content_digest_sha256"] == FROZEN_BASELINE_DIGEST_SHA256
    assert digest == FROZEN_BASELINE_DIGEST_SHA256


def test_compute_dataset_digest_is_idempotent() -> None:
    first = compute_dataset_digest(BASELINE_JSONL)
    second = compute_dataset_digest(BASELINE_JSONL)
    assert first == second == FROZEN_BASELINE_DIGEST_SHA256


def test_dataset_digest_stable_after_copy(tmp_path: Path) -> None:
    copy = tmp_path / "baseline_copy.jsonl"
    copy.write_bytes(BASELINE_JSONL.read_bytes())
    assert compute_dataset_digest(copy) == FROZEN_BASELINE_DIGEST_SHA256


# --- installed / packaged resource smoke (importlib.resources) ---


@pytest.mark.parametrize(
    "relative_path",
    [
        "schemas/evaluation_case.v1.json",
        "schemas/evaluation_manifest.v1.json",
        "schemas/evaluation_run_provenance.v1.json",
        "schemas/schema.json",
        "schemas/evaluation_schema.json",
        "datasets/baseline.jsonl",
        "datasets/baseline.manifest.json",
    ],
)
def test_packaged_eval_resources_are_readable(relative_path: str) -> None:
    resource = files("src.resources").joinpath(relative_path)
    with as_file(resource) as packaged:
        assert Path(packaged).is_file()
        assert Path(packaged).stat().st_size > 0


def test_packaged_baseline_bytes_match_repo_source_tree() -> None:
    resource = files("src.resources").joinpath("datasets/baseline.jsonl")
    with as_file(resource) as packaged:
        assert Path(packaged).read_bytes() == BASELINE_JSONL.read_bytes()


def test_packaged_manifest_matches_repo_baseline_manifest() -> None:
    resource = files("src.resources").joinpath("datasets/baseline.manifest.json")
    with as_file(resource) as packaged:
        packaged_manifest = load_dataset_manifest(Path(packaged))
    repo_manifest = load_dataset_manifest(BASELINE_MANIFEST)
    assert packaged_manifest == repo_manifest


def test_resolve_dataset_manifest_via_packaged_digest_match(tmp_path: Path) -> None:
    """Ungoverned path: same bytes as baseline resolve packaged manifest by digest."""
    lone = tmp_path / "orphan.jsonl"
    lone.write_bytes(BASELINE_JSONL.read_bytes())
    resolved = resolve_dataset_manifest(lone)
    assert resolved is not None
    assert resolved["content_digest_sha256"] == FROZEN_BASELINE_DIGEST_SHA256


# --- baseline smoke (known data) ---


def test_baseline_validate_passes_with_parity() -> None:
    manifest = validate_dataset(BASELINE_JSONL, check_packaged_parity=True)
    assert manifest is not None
    assert manifest["contract_id"] == CONTRACT_DATASET_V1
    assert manifest["case_count"] == 50


def test_baseline_case_id_ordering_matches_manifest() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    validate_dataset_against_manifest(BASELINE_JSONL, manifest)
    ids_from_file: list[str] = []
    for line in BASELINE_JSONL.read_text(encoding="utf-8").splitlines():
        if line.strip():
            ids_from_file.append(json.loads(line)["case_id"])
    assert ids_from_file == manifest["case_ids"]
    assert len(ids_from_file) == len(set(ids_from_file))


def test_baseline_family_counts_match_rows() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    counts: dict[str, int] = {}
    for line in BASELINE_JSONL.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        family = json.loads(line).get("attack_family") or "unknown"
        counts[family] = counts.get(family, 0) + 1
    assert counts == dict(manifest["family_counts"])


# --- required field labels, families, ordering (fail-closed) ---


def test_validate_evaluation_row_enforces_required_field_labels(tmp_path: Path) -> None:
    row = _minimal_row()
    del row["attack_family"]
    with pytest.raises(EvaluationContractError, match="requires field 'attack_family'"):
        validate_evaluation_row(
            row,
            1,
            required_fields=["case_id", "attack_family"],
            allowed_case_types=["benign"],
            allowed_risk_levels=["low"],
        )


def test_validate_evaluation_row_rejects_disallowed_risk_level() -> None:
    row = _minimal_row(expected_risk_level="forbidden")
    with pytest.raises(EvaluationContractError, match="forbidden"):
        validate_evaluation_row(
            row,
            2,
            required_fields=None,
            allowed_case_types=["benign"],
            allowed_risk_levels=["low", "medium"],
        )


def test_validate_manifest_rejects_family_counts_sum_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "one.jsonl"
    dataset.write_text(json.dumps(_minimal_row()) + "\n", encoding="utf-8")
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    bad = dict(manifest)
    bad["dataset_filename"] = dataset.name
    bad["content_digest_sha256"] = compute_dataset_digest(dataset)
    bad["case_count"] = 1
    bad["case_ids"] = ["case_one"]
    bad["family_counts"] = {"clean": 2}
    with pytest.raises(EvaluationContractError, match="family_counts sum"):
        validate_manifest_document(bad, dataset_path=dataset)


def test_validate_dataset_against_manifest_rejects_ordering_mismatch(tmp_path: Path) -> None:
    dataset = tmp_path / "order.jsonl"
    rows = [_minimal_row(case_id="a"), _minimal_row(case_id="b")]
    dataset.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    bad = dict(manifest)
    bad["dataset_filename"] = dataset.name
    bad["content_digest_sha256"] = compute_dataset_digest(dataset)
    bad["case_count"] = 2
    bad["case_ids"] = ["b", "a"]
    bad["family_counts"] = {"clean": 2}
    with pytest.raises(EvaluationContractError, match="ordering"):
        validate_dataset_against_manifest(dataset, bad)


@pytest.mark.parametrize(
    "payload,match",
    [
        ('{"case_id":"x"}\n', "schema violation"),
        ("not json\n", "invalid JSON"),
        (
            json.dumps(_minimal_row(case_id="dup"))
            + "\n"
            + json.dumps(_minimal_row(case_id="dup"))
            + "\n",
            "duplicate",
        ),
    ],
)
def test_fail_closed_on_malformed_jsonl(tmp_path: Path, payload: str, match: str) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text(payload, encoding="utf-8")
    with pytest.raises(EvaluationContractError, match=match):
        validate_dataset(path, check_packaged_parity=False)


# --- CLI smoke (installed entrypoint + scripts) ---


def test_adml_validate_cli_succeeds_on_baseline() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "src.cli", "validate", str(BASELINE_JSONL), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_scripts_validate_py_succeeds_on_baseline() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/validate.py"), str(BASELINE_JSONL), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
