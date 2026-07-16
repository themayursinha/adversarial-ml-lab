#!/usr/bin/env python3
"""Integration smoke: baseline validation, digests, corruption probes, package parity."""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))

from src.eval.contract import (  # noqa: E402
    EvaluationContractError,
    compute_dataset_digest,
    load_dataset_manifest,
)
from src.eval.validator import generate_run_metadata, validate_dataset  # noqa: E402
from src.utils.llm_client import LLMMode  # noqa: E402

EVALS_JSONL = REPO / "evals/datasets/baseline.jsonl"
EVALS_MANIFEST = REPO / "evals/datasets/baseline.manifest.json"
PKG_JSONL = REPO / "src/resources/datasets/baseline.jsonl"
PKG_MANIFEST = REPO / "src/resources/datasets/baseline.manifest.json"
EXPECTED_DIGEST = "99a6515f3488f25e4ebaaf44880b42779b5671bd0045d92f793d37b475baded9"


def _ok(msg: str) -> None:
    print(f"PASS: {msg}")


def _fail(msg: str) -> None:
    print(f"FAIL: {msg}", file=sys.stderr)
    sys.exit(1)


def main() -> None:
    print("=== baseline smoke: digests ===")
    for label, path in [("evals", EVALS_JSONL), ("packaged", PKG_JSONL)]:
        digest = compute_dataset_digest(path)
        print(f"  {label} sha256={digest}")
        if digest != EXPECTED_DIGEST:
            _fail(f"{label} digest mismatch (expected {EXPECTED_DIGEST})")
    _ok("both copies match frozen digest")

    print("=== baseline smoke: manifest parity ===")
    repo_m = load_dataset_manifest(EVALS_MANIFEST)
    pkg_m = load_dataset_manifest(PKG_MANIFEST)
    if repo_m != pkg_m:
        _fail("evals vs packaged manifest differ")
    if EVALS_JSONL.read_bytes() != PKG_JSONL.read_bytes():
        _fail("evals vs packaged jsonl bytes differ")
    _ok("repo and packaged manifest+jsonl parity")

    print("=== baseline smoke: validate_dataset (good data) ===")
    m_evals = validate_dataset(EVALS_JSONL)
    m_pkg = validate_dataset(PKG_JSONL)
    if m_evals is None or m_pkg is None:
        _fail("expected governed manifest for baseline")
    assert m_evals is not None
    if m_evals["case_count"] != 50:
        _fail(f"case_count={m_evals['case_count']}")
    _ok("validate_dataset accepts evals and packaged baseline")

    print("=== baseline smoke: corruption probes ===")
    with tempfile.TemporaryDirectory() as tmp:
        tdir = Path(tmp)
        bad_digest = tdir / "bad_digest.jsonl"
        shutil.copy(EVALS_JSONL, bad_digest)
        manifest = json.loads(EVALS_MANIFEST.read_text(encoding="utf-8"))
        manifest["content_digest_sha256"] = "0" * 64
        try:
            validate_dataset(bad_digest, manifest)
            _fail("digest mismatch should raise")
        except EvaluationContractError as exc:
            if "digest" not in str(exc).lower():
                _fail(f"unexpected error: {exc}")
        _ok("rejects digest mismatch")

        dup = tdir / "dup.jsonl"
        lines = EVALS_JSONL.read_text(encoding="utf-8").strip().split("\n")
        dup.write_text(lines[0] + "\n" + lines[0] + "\n", encoding="utf-8")
        try:
            validate_dataset(dup)
            _fail("duplicate case_id should raise")
        except EvaluationContractError:
            pass
        _ok("rejects duplicate case_id (ungoverned)")

        corrupt = tdir / "corrupt.jsonl"
        corrupt.write_text("{not json}\n", encoding="utf-8")
        try:
            validate_dataset(corrupt)
            _fail("malformed json should raise")
        except EvaluationContractError:
            pass
        _ok("rejects malformed JSON")

        parity_manifest = json.loads(EVALS_MANIFEST.read_text(encoding="utf-8"))
        tampered = tdir / "tampered.jsonl"
        lines = EVALS_JSONL.read_text(encoding="utf-8").strip().split("\n")
        row = json.loads(lines[0])
        row["prompt"] = row["prompt"] + " "
        lines[0] = json.dumps(row, separators=(",", ":"))
        tampered.write_text("\n".join(lines) + "\n", encoding="utf-8")
        parity_manifest["dataset_filename"] = tampered.name
        parity_manifest["content_digest_sha256"] = compute_dataset_digest(tampered)
        try:
            validate_dataset(tampered, parity_manifest, check_packaged_parity=True)
            _fail("source/package parity should raise")
        except EvaluationContractError as exc:
            if "parity" not in str(exc).lower():
                _fail(f"unexpected parity error: {exc}")
        _ok("rejects source/package parity violation")

    print("=== baseline smoke: run metadata ===")
    meta = generate_run_metadata(
        dataset_path=EVALS_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    if meta["dataset"]["content_digest_sha256"] != EXPECTED_DIGEST:
        _fail("provenance digest mismatch")
    if meta["runtime"]["llm_mode"] != "simulation":
        _fail("expected simulation llm_mode")
    _ok("generate_run_metadata digest + simulation mode")

    print("=== baseline smoke: ALL CHECKS PASSED ===")


if __name__ == "__main__":
    main()
