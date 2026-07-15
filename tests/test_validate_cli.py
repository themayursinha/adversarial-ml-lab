"""CLI tests for evaluation JSONL validation (fail-closed)."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

from src.eval.contract import MANIFEST_VERSION, compute_dataset_digest
from src.eval.validate import main as validate_main
from src.eval.validate import run_validate_command

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"


def _minimal_valid_row(case_id: str = "case_one") -> dict:
    return {
        "case_id": case_id,
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
        "case_type": "benign",
        "attack_family": "clean",
    }


def test_validate_cli_accepts_baseline_json(capsys) -> None:
    code = run_validate_command(
        Namespace(
            dataset=str(BASELINE_JSONL),
            dataset_opt=None,
            manifest=None,
            no_packaged_parity=False,
            json=True,
            quiet=False,
        )
    )
    out = capsys.readouterr().out
    assert code == 0
    payload = json.loads(out)
    assert payload["status"] == "ok"
    assert payload["governed"] is True
    assert payload["case_count"] == 50


def test_validate_cli_rejects_duplicate_ids(tmp_path, capsys) -> None:
    dataset = tmp_path / "dup.jsonl"
    rows = [_minimal_valid_row("dup_id"), _minimal_valid_row("dup_id")]
    dataset.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    code = validate_main([str(dataset)])
    err = capsys.readouterr().err
    assert code == 1
    assert "validation failed" in err
    assert "duplicate" in err.lower() or "unique" in err.lower()


def test_validate_cli_rejects_malformed_json(tmp_path, capsys) -> None:
    dataset = tmp_path / "bad.jsonl"
    dataset.write_text("{not json}\n", encoding="utf-8")
    code = validate_main([str(dataset)])
    err = capsys.readouterr().err
    assert code == 1
    assert "invalid JSON" in err or "validation failed" in err


def test_validate_cli_rejects_family_counts_mismatch(tmp_path, capsys) -> None:
    dataset = tmp_path / "suite.jsonl"
    row = _minimal_valid_row("only_one")
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "contract_id": "adml.evaluation.dataset.v1",
        "suite_name": "mismatch",
        "dataset_filename": dataset.name,
        "content_digest_sha256": compute_dataset_digest(dataset),
        "case_count": 1,
        "case_ids": ["only_one"],
        "family_counts": {"clean": 2},
        "schema_ref": "evaluation_case.v1",
        "required_fields": list(row.keys()),
        "allowed_case_types": ["benign"],
        "allowed_risk_levels": ["low"],
    }
    manifest_path = tmp_path / "suite.manifest.json"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    code = validate_main([str(dataset), "--manifest", str(manifest_path)])
    err = capsys.readouterr().err
    assert code == 1
    assert "family_counts" in err


def test_scripts_validate_py_exit_codes() -> None:
    script = REPO_ROOT / "scripts/validate.py"
    good = subprocess.run(
        [sys.executable, str(script), str(BASELINE_JSONL), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert good.returncode == 0

    bad = subprocess.run(
        [sys.executable, str(script), str(REPO_ROOT / "missing.jsonl")],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert bad.returncode != 0
    assert "not found" in bad.stderr.lower() or "validation failed" in bad.stderr.lower()


def test_adml_validate_subprocess_accepts_baseline() -> None:
    proc = subprocess.run(
        [sys.executable, "-m", "src.cli", "validate", str(BASELINE_JSONL), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
