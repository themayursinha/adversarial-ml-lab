"""Unit tests for deterministic run metadata generation (metadata.py)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from src.eval.contract import (
    EvaluationContractError,
    compute_dataset_digest,
    evaluation_run_provenance_schema,
)
from src.eval.metadata import (
    RunContext,
    assert_metadata_dataset_digest,
    build_run_metadata,
    compute_config_fingerprint_sha256,
    frozen_metric_definitions,
    resolve_code_commit_sha,
)
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"


def test_build_run_metadata_matches_provenance_schema() -> None:
    context = RunContext.for_dataset(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    metadata = build_run_metadata(context)
    validator = Draft202012Validator(evaluation_run_provenance_schema())
    errors = sorted(validator.iter_errors(metadata), key=lambda err: list(err.path))
    assert not errors


def test_build_run_metadata_dataset_digest_matches_file() -> None:
    context = RunContext.for_dataset(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    metadata = build_run_metadata(context)
    assert metadata["dataset"]["content_digest_sha256"] == compute_dataset_digest(
        BASELINE_JSONL
    )
    assert_metadata_dataset_digest(metadata, BASELINE_JSONL)


def test_build_run_metadata_is_deterministic_for_identical_context() -> None:
    context = RunContext.for_dataset(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
        code_commit_sha="a" * 40,
        config_fingerprint_sha256=compute_config_fingerprint_sha256(),
        metric_definitions=frozen_metric_definitions(),
    )
    first = build_run_metadata(context)
    second = build_run_metadata(context)
    assert first == second
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


def test_build_run_metadata_includes_explicit_code_commit_sha() -> None:
    commit_sha = "a" * 40
    context = RunContext.for_dataset(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
        code_commit_sha=commit_sha,
    )

    metadata = build_run_metadata(context)

    assert metadata["code"]["commit_sha"] == commit_sha


def test_compute_config_fingerprint_is_stable() -> None:
    a = compute_config_fingerprint_sha256()
    b = compute_config_fingerprint_sha256()
    assert a == b
    assert len(a) == 64


def test_run_context_rejects_invalid_code_commit() -> None:
    with pytest.raises(EvaluationContractError, match="code_commit_sha"):
        RunContext.for_dataset(
            dataset_path=BASELINE_JSONL,
            suite_name="baseline",
            llm_mode=LLMMode.SIMULATION,
            code_commit_sha="not-a-sha",
        )


def test_resolve_code_commit_sha_in_git_worktree() -> None:
    sha = resolve_code_commit_sha(REPO_ROOT)
    if sha is not None:
        assert len(sha) == 40
        assert sha.islower()
