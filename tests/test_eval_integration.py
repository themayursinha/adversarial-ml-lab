"""Integration tests tying validator, metadata, parity, and CLIs together."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path

import pytest

from src.eval.contract import EvaluationContractError, compute_dataset_digest, load_dataset_manifest
from src.eval.metadata import RunContext, assert_metadata_dataset_digest, build_run_metadata
from src.eval.parity import check_baseline_pair, default_baseline_locations
from src.eval.validate import run_validate, run_validate_command
from src.eval.validator import generate_run_metadata, validate_dataset
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"


def test_baseline_validate_metadata_parity_chain() -> None:
    """Governed baseline passes validation, parity gate, and metadata digest checks."""
    manifest = run_validate(BASELINE_JSONL, check_packaged_parity=True)
    assert manifest is not None
    assert manifest["case_count"] == 50

    parity_summary = check_baseline_pair(default_baseline_locations(REPO_ROOT))
    assert parity_summary["status"] == "ok"
    assert parity_summary["content_digest_sha256"] == manifest["content_digest_sha256"]

    meta = generate_run_metadata(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
        manifest=manifest,
    )
    assert_metadata_dataset_digest(meta, BASELINE_JSONL)
    assert meta["dataset"]["suite_name"] == "baseline"


def test_validated_custom_dataset_produces_consistent_metadata(tmp_path: Path) -> None:
    row = {
        "case_id": "integration_one",
        "prompt": "hello",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
        "case_type": "benign",
        "attack_family": "clean",
    }
    dataset = tmp_path / "suite.jsonl"
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    from src.eval.contract import CONTRACT_DATASET_V1, MANIFEST_VERSION

    manifest = {
        "manifest_version": MANIFEST_VERSION,
        "contract_id": CONTRACT_DATASET_V1,
        "suite_name": "integration",
        "dataset_filename": dataset.name,
        "content_digest_sha256": compute_dataset_digest(dataset),
        "case_count": 1,
        "case_ids": ["integration_one"],
        "family_counts": {"clean": 1},
        "schema_ref": "evaluation_case.v1",
        "required_fields": list(row.keys()),
        "allowed_case_types": ["benign"],
        "allowed_risk_levels": ["low"],
    }
    validate_dataset(dataset, manifest, check_packaged_parity=False)

    meta = build_run_metadata(
        RunContext.for_dataset(
            dataset_path=dataset,
            suite_name="integration",
            llm_mode=LLMMode.SIMULATION,
            manifest=manifest,
        )
    )
    assert meta["dataset"]["case_count"] == 1
    assert meta["dataset"]["content_digest_sha256"] == compute_dataset_digest(dataset)


def test_validate_then_metadata_fails_when_dataset_tampered_after_validation(
    tmp_path: Path,
) -> None:
    dataset = tmp_path / "tamper.jsonl"
    dataset.write_text(
        json.dumps(
            {
                "case_id": "x",
                "prompt": "p",
                "context": "",
                "task_type": "chat",
                "expected_blocked": False,
                "case_type": "benign",
                "attack_family": "clean",
            }
        )
        + "\n",
        encoding="utf-8",
    )
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    bad = dict(manifest)
    bad["case_count"] = 1
    bad["case_ids"] = ["x"]
    bad["family_counts"] = {"clean": 1}
    bad["content_digest_sha256"] = "f" * 64
    with pytest.raises(EvaluationContractError):
        build_run_metadata(
            RunContext.for_dataset(
                dataset_path=dataset,
                suite_name="tamper",
                llm_mode=LLMMode.SIMULATION,
                manifest=bad,
            )
        )


def test_parity_and_validate_clis_succeed_on_repo(capsys) -> None:
    vcode = run_validate_command(
        Namespace(
            dataset=str(BASELINE_JSONL),
            dataset_opt=None,
            manifest=None,
            no_packaged_parity=False,
            json=False,
            quiet=True,
        )
    )
    assert vcode == 0

    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/parity.py"), "--json", "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["status"] == "ok"


def test_evidence_parent_tasks_modules_importable() -> None:
    """Smoke that validator, metadata, and parity public surfaces exist."""
    from src.eval import metadata as metadata_mod
    from src.eval import parity as parity_mod
    from src.eval import validate as validate_mod
    from src.eval import validator as validator_mod

    assert callable(validator_mod.validate_dataset)
    assert callable(validator_mod.generate_run_metadata)
    assert callable(metadata_mod.build_run_metadata)
    assert callable(parity_mod.check_baseline_pair)
    assert callable(validate_mod.run_validate)
