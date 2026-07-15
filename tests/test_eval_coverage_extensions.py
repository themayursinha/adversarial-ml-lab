"""Additional unit tests for validate, metadata, parity, and validator edge cases."""

from __future__ import annotations

import json
import subprocess
import sys
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

from src.eval.contract import EvaluationContractError
from src.eval.metadata import (
    RunContext,
    assert_metadata_dataset_digest,
    build_run_metadata,
    compute_config_fingerprint_sha256,
    resolve_code_commit_sha,
)
from src.eval.parity import (
    assert_manifest_digest_matches_dataset,
    extract_ordered_case_ids,
    run_parity_command,
)
from src.eval.validate import run_validate_command
from src.eval.validator import assert_packaged_resource_parity
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"


# --- validate.py ---


def test_validate_cli_missing_dataset_path(capsys) -> None:
    code = run_validate_command(
        Namespace(
            dataset=None,
            dataset_opt=None,
            manifest=None,
            no_packaged_parity=False,
            json=False,
            quiet=False,
        )
    )
    assert code == 1
    assert "required" in capsys.readouterr().err.lower()


def test_validate_cli_missing_dataset_file(tmp_path: Path, capsys) -> None:
    missing = tmp_path / "nope.jsonl"
    code = run_validate_command(
        Namespace(
            dataset=str(missing),
            dataset_opt=None,
            manifest=None,
            no_packaged_parity=False,
            json=False,
            quiet=False,
        )
    )
    assert code == 1
    assert "not found" in capsys.readouterr().err.lower()


def test_validate_cli_missing_manifest_file(capsys) -> None:
    code = run_validate_command(
        Namespace(
            dataset=str(BASELINE_JSONL),
            dataset_opt=None,
            manifest=str(REPO_ROOT / "missing.manifest.json"),
            no_packaged_parity=False,
            json=False,
            quiet=False,
        )
    )
    assert code == 1
    assert "manifest not found" in capsys.readouterr().err.lower()


def test_validate_cli_success_human_message(capsys) -> None:
    code = run_validate_command(
        Namespace(
            dataset=str(BASELINE_JSONL),
            dataset_opt=None,
            manifest=None,
            no_packaged_parity=False,
            json=False,
            quiet=False,
        )
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "ok:" in out


# --- metadata.py ---


def test_run_context_rejects_blank_suite_name() -> None:
    with pytest.raises(EvaluationContractError, match="suite_name"):
        RunContext.for_dataset(
            dataset_path=BASELINE_JSONL,
            suite_name="   ",
            llm_mode=LLMMode.SIMULATION,
        )


def test_run_context_rejects_bad_config_fingerprint() -> None:
    with pytest.raises(EvaluationContractError, match="config_fingerprint"):
        RunContext.for_dataset(
            dataset_path=BASELINE_JSONL,
            suite_name="baseline",
            llm_mode=LLMMode.SIMULATION,
            config_fingerprint_sha256="not-hex",
        )


def test_build_run_metadata_rejects_empty_metric_definitions() -> None:
    context = RunContext.for_dataset(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
        metric_definitions={},
    )
    with pytest.raises(EvaluationContractError, match="metric_definitions"):
        build_run_metadata(context)


def test_assert_metadata_dataset_digest_mismatch(tmp_path: Path) -> None:
    meta = {
        "dataset": {
            "content_digest_sha256": "a" * 64,
        }
    }
    with pytest.raises(EvaluationContractError, match="digest"):
        assert_metadata_dataset_digest(meta, BASELINE_JSONL)


def test_resolve_code_commit_sha_returns_none_outside_git(tmp_path: Path) -> None:
    assert resolve_code_commit_sha(tmp_path) is None


def test_compute_config_fingerprint_uses_omegaconf_branch() -> None:
    with patch("src.eval.metadata.is_dataclass", return_value=False):
        with patch("src.eval.metadata.OmegaConf") as omega:
            omega.to_container.return_value = {"k": 1}
            digest = compute_config_fingerprint_sha256()
    assert len(digest) == 64


# --- parity.py ---


def test_extract_ordered_case_ids_rejects_blank_line(tmp_path: Path) -> None:
    path = tmp_path / "blank.jsonl"
    path.write_text('{"case_id":"a"}\n\n', encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="empty line"):
        extract_ordered_case_ids(path)


def test_extract_ordered_case_ids_rejects_missing_case_id(tmp_path: Path) -> None:
    path = tmp_path / "bad.jsonl"
    path.write_text('{"prompt":"x"}\n', encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="case_id"):
        extract_ordered_case_ids(path)


def test_assert_manifest_digest_matches_dataset_wrong_digest(tmp_path: Path) -> None:
    path = tmp_path / "one.jsonl"
    path.write_text('{"case_id":"x"}\n', encoding="utf-8")
    manifest = {"content_digest_sha256": "b" * 64}
    with pytest.raises(EvaluationContractError, match="digest mismatch"):
        assert_manifest_digest_matches_dataset(path, manifest)


def test_assert_manifest_digest_requires_string_digest() -> None:
    with pytest.raises(EvaluationContractError, match="content_digest_sha256"):
        assert_manifest_digest_matches_dataset(BASELINE_JSONL, {})


def test_parity_cli_json_success(capsys) -> None:
    code = run_parity_command(
        Namespace(
            repo_root=REPO_ROOT,
            no_packaged_parity=False,
            json=True,
            quiet=False,
        )
    )
    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(out)["status"] == "ok"


def test_scripts_parity_py_exit_code() -> None:
    proc = subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts/parity.py"), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_check_baseline_pair_missing_artifact(tmp_path: Path) -> None:
    from src.eval.parity import BaselineLocations, check_baseline_pair

    loc = BaselineLocations(
        source_jsonl=tmp_path / "missing.jsonl",
        source_manifest=tmp_path / "missing.manifest.json",
        packaged_jsonl=tmp_path / "p.jsonl",
        packaged_manifest=tmp_path / "p.manifest.json",
    )
    with pytest.raises(EvaluationContractError, match="missing baseline"):
        check_baseline_pair(loc)


# --- validator.py ---


def test_packaged_resource_parity_skips_empty_string(tmp_path: Path) -> None:
    dataset = tmp_path / "d.jsonl"
    dataset.write_text('{"case_id":"x"}\n', encoding="utf-8")
    assert_packaged_resource_parity({"packaged_resource": "   "}, dataset)


def test_packaged_resource_missing_raises(tmp_path: Path) -> None:
    dataset = tmp_path / "d.jsonl"
    dataset.write_text('{"case_id":"x"}\n', encoding="utf-8")
    with pytest.raises(EvaluationContractError, match="not available"):
        assert_packaged_resource_parity(
            {"packaged_resource": "datasets/no_such_file.jsonl"},
            dataset,
        )


def test_validate_cli_ungoverned_success_message(tmp_path: Path, capsys) -> None:
    row = {
        "case_id": "solo",
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
        "case_type": "benign",
        "attack_family": "clean",
    }
    dataset = tmp_path / "solo.jsonl"
    dataset.write_text(json.dumps(row) + "\n", encoding="utf-8")
    code = run_validate_command(
        Namespace(
            dataset=str(dataset),
            dataset_opt=None,
            manifest=None,
            no_packaged_parity=True,
            json=False,
            quiet=False,
        )
    )
    out = capsys.readouterr().out
    assert code == 0
    assert "schema + unique case_ids" in out


def test_parity_cli_failure_reports_error(tmp_path: Path, capsys) -> None:
    code = run_parity_command(
        Namespace(
            repo_root=tmp_path,
            no_packaged_parity=True,
            json=False,
            quiet=True,
        )
    )
    err = capsys.readouterr().err
    assert code == 1
    assert "parity gate failed" in err
