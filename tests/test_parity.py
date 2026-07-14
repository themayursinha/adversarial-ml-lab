"""Tests for baseline source/package parity gate checks."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from src.eval.contract import EvaluationContractError, compute_dataset_digest
from src.eval.parity import (
    BaselineLocations,
    assert_case_id_ordering_matches_manifest,
    assert_dataset_bytes_equal,
    assert_manifest_documents_equal,
    check_baseline_pair,
    default_baseline_locations,
    extract_ordered_case_ids,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"


def test_default_baseline_locations_point_at_repo_copies() -> None:
    loc = default_baseline_locations(REPO_ROOT)
    assert loc.source_jsonl == BASELINE_JSONL
    assert loc.packaged_jsonl.name == "baseline.jsonl"
    assert loc.packaged_manifest.parent.name == "datasets"


def test_extract_ordered_case_ids_matches_manifest_on_baseline() -> None:
    manifest = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
    observed = extract_ordered_case_ids(BASELINE_JSONL)
    assert observed == manifest["case_ids"]
    assert len(observed) == manifest["case_count"]


def test_check_baseline_pair_passes_on_matching_copies() -> None:
    summary = check_baseline_pair(default_baseline_locations(REPO_ROOT))
    assert summary["status"] == "ok"
    assert summary["case_count"] == 50
    assert summary["suite_name"] == "baseline"
    assert summary["content_digest_sha256"] == manifest_digest_from_file()


def test_assert_manifest_documents_equal_detects_field_drift() -> None:
    left = {"a": 1, "b": 2}
    right = {"a": 1, "b": 3}
    with pytest.raises(EvaluationContractError, match="manifest mismatch"):
        assert_manifest_documents_equal(left, right)


def test_assert_dataset_bytes_equal_detects_tamper(tmp_path: Path) -> None:
    a = tmp_path / "a.jsonl"
    b = tmp_path / "b.jsonl"
    a.write_text('{"case_id":"x"}\n', encoding="utf-8")
    b.write_text('{"case_id":"y"}\n', encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="dataset bytes differ"):
        assert_dataset_bytes_equal(a, b)


def test_ordering_check_rejects_permuted_manifest(tmp_path: Path) -> None:
    shutil.copy(BASELINE_JSONL, tmp_path / "data.jsonl")
    manifest = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
    ids = list(manifest["case_ids"])
    manifest["case_ids"] = [ids[1], ids[0], *ids[2:]]
    with pytest.raises(EvaluationContractError, match="ordering"):
        assert_case_id_ordering_matches_manifest(tmp_path / "data.jsonl", manifest)


def test_check_baseline_pair_fails_on_manifest_mismatch(tmp_path: Path) -> None:
    source_jsonl = tmp_path / "evals" / "baseline.jsonl"
    source_manifest = tmp_path / "evals" / "baseline.manifest.json"
    packaged_jsonl = tmp_path / "pkg" / "baseline.jsonl"
    packaged_manifest = tmp_path / "pkg" / "baseline.manifest.json"
    for path in (source_jsonl, source_manifest, packaged_jsonl, packaged_manifest):
        path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy(BASELINE_JSONL, source_jsonl)
    shutil.copy(BASELINE_JSONL, packaged_jsonl)
    shutil.copy(BASELINE_MANIFEST, source_manifest)
    pkg_manifest = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
    pkg_manifest["suite_name"] = "not-baseline"
    packaged_manifest.write_text(json.dumps(pkg_manifest, indent=2) + "\n", encoding="utf-8")

    locations = BaselineLocations(
        source_jsonl=source_jsonl,
        source_manifest=source_manifest,
        packaged_jsonl=packaged_jsonl,
        packaged_manifest=packaged_manifest,
    )
    with pytest.raises(EvaluationContractError, match="manifest mismatch"):
        check_baseline_pair(locations, check_packaged_parity=False)


def test_check_baseline_pair_fails_on_jsonl_byte_mismatch(tmp_path: Path) -> None:
    source_jsonl = tmp_path / "evals" / "baseline.jsonl"
    source_manifest = tmp_path / "evals" / "baseline.manifest.json"
    packaged_jsonl = tmp_path / "pkg" / "baseline.jsonl"
    packaged_manifest = tmp_path / "pkg" / "baseline.manifest.json"
    for path in (source_jsonl, source_manifest, packaged_jsonl, packaged_manifest):
        path.parent.mkdir(parents=True, exist_ok=True)

    shutil.copy(BASELINE_JSONL, source_jsonl)
    shutil.copy(BASELINE_MANIFEST, source_manifest)
    shutil.copy(BASELINE_MANIFEST, packaged_manifest)

    lines = BASELINE_JSONL.read_text(encoding="utf-8").strip().split("\n")
    row = json.loads(lines[0])
    row["prompt"] = row["prompt"] + " tamper"
    lines[0] = json.dumps(row, separators=(",", ":"))
    packaged_jsonl.write_text("\n".join(lines) + "\n", encoding="utf-8")

    manifest = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
    manifest["content_digest_sha256"] = compute_dataset_digest(packaged_jsonl)
    packaged_manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

    locations = BaselineLocations(
        source_jsonl=source_jsonl,
        source_manifest=source_manifest,
        packaged_jsonl=packaged_jsonl,
        packaged_manifest=packaged_manifest,
    )
    with pytest.raises(EvaluationContractError, match="manifest mismatch|dataset bytes differ"):
        check_baseline_pair(locations, check_packaged_parity=False)


def manifest_digest_from_file() -> str:
    manifest = json.loads(BASELINE_MANIFEST.read_text(encoding="utf-8"))
    return str(manifest["content_digest_sha256"])
