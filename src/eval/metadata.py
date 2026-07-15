"""Deterministic run metadata generation for evaluation result manifests."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from dataclasses import asdict, dataclass, is_dataclass
from pathlib import Path
from typing import Any, Mapping

from omegaconf import OmegaConf

from src import __version__
from src.config.loader import get_default_config
from src.eval.contract import (
    CONTRACT_RUN_V1,
    EvaluationContractError,
    compute_dataset_digest,
    evaluation_run_provenance_schema,
    resolve_dataset_manifest,
    validate_dataset_against_manifest,
    validate_json_document,
)
from src.utils.llm_client import LLMMode

_COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")
_DIGEST_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")


@dataclass(frozen=True)
class RunContext:
    """
    Inputs that fully determine the run provenance block for a single evaluation.

    Identical contexts produce byte-identical metadata dictionaries (modulo manifest
    resolution when ``manifest`` is omitted and the dataset file is unchanged).
    """

    dataset_path: Path
    suite_name: str
    llm_mode: LLMMode
    manifest: dict[str, Any] | None = None
    code_commit_sha: str | None = None
    config_fingerprint_sha256: str | None = None
    simulation_seed: None = None
    metric_definitions: Mapping[str, str] | None = None
    package_version: str = __version__

    def __post_init__(self) -> None:
        if not self.suite_name.strip():
            raise EvaluationContractError("suite_name must be a non-empty string")
        if self.code_commit_sha is not None and not _COMMIT_SHA_PATTERN.fullmatch(
            self.code_commit_sha
        ):
            raise EvaluationContractError(
                "code_commit_sha must be a 40-character lowercase git SHA when set"
            )
        if (
            self.config_fingerprint_sha256 is not None
            and not _DIGEST_SHA256_PATTERN.fullmatch(self.config_fingerprint_sha256)
        ):
            raise EvaluationContractError(
                "config_fingerprint_sha256 must be a 64-character lowercase hex string"
            )

    @classmethod
    def for_dataset(
        cls,
        *,
        dataset_path: Path,
        suite_name: str,
        llm_mode: LLMMode,
        manifest: dict[str, Any] | None = None,
        code_commit_sha: str | None = None,
        config_fingerprint_sha256: str | None = None,
        metric_definitions: Mapping[str, str] | None = None,
        package_version: str | None = None,
    ) -> RunContext:
        """Build a context from dataset path and runtime knobs (v1 simulation seed is fixed null)."""
        return cls(
            dataset_path=Path(dataset_path),
            suite_name=suite_name,
            llm_mode=llm_mode,
            manifest=manifest,
            code_commit_sha=code_commit_sha,
            config_fingerprint_sha256=config_fingerprint_sha256,
            simulation_seed=None,
            metric_definitions=metric_definitions,
            package_version=package_version or __version__,
        )


def frozen_metric_definitions() -> dict[str, str]:
    """Immutable metric definitions embedded in every run metadata block."""
    return {
        "pass_rate": (
            "Fraction of cases where observed blocked/not-blocked matches expected_blocked."
        ),
        "blocked_cases": "Count of cases where the defense pipeline blocked model output.",
        "review_cases": "Count of cases flagged for human review by the pipeline.",
        "review_match_rate": (
            "Among cases with expected_review set, fraction where needs_human_review matches."
        ),
        "risk_match_rate": (
            "Among cases with expected_risk_level set, fraction where detection risk_level matches."
        ),
        "family_metrics": (
            "Per attack_family aggregates: total_cases, blocked_cases, review_cases, pass_rate."
        ),
    }


def compute_config_fingerprint_sha256() -> str:
    """Deterministic digest of the canonical default defense/LLM configuration."""
    config = get_default_config()
    if is_dataclass(config):
        payload = asdict(config)
    else:
        payload = OmegaConf.to_container(config, resolve=True)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def resolve_code_commit_sha(repo_root: Path | None = None) -> str | None:
    """Return the current git HEAD SHA when available (optional run-context input)."""
    root = repo_root or Path(__file__).resolve().parents[2]
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return None
    sha = completed.stdout.strip().lower()
    if _COMMIT_SHA_PATTERN.fullmatch(sha):
        return sha
    return None


def _resolved_config_fingerprint(context: RunContext) -> str:
    if context.config_fingerprint_sha256 is not None:
        return context.config_fingerprint_sha256
    return compute_config_fingerprint_sha256()


def _resolved_code_commit_sha(context: RunContext) -> str | None:
    if context.code_commit_sha is not None:
        return context.code_commit_sha
    return resolve_code_commit_sha()


def _resolved_metric_definitions(context: RunContext) -> dict[str, str]:
    if context.metric_definitions is None:
        return dict(frozen_metric_definitions())
    if not context.metric_definitions:
        raise EvaluationContractError("metric_definitions must not be empty when provided")
    return dict(context.metric_definitions)


def build_run_metadata(context: RunContext) -> dict[str, Any]:
    """
    Produce the structured provenance block for a result manifest.

    Output conforms to ``evaluation_run_provenance.v1.json``. Dataset digest is
    always computed from on-disk bytes at build time.
    """
    dataset_path = Path(context.dataset_path)
    manifest = context.manifest if context.manifest is not None else resolve_dataset_manifest(
        dataset_path
    )
    if manifest is not None:
        validate_dataset_against_manifest(dataset_path, manifest)

    dataset_digest = compute_dataset_digest(dataset_path)
    metadata = {
        "contract_id": CONTRACT_RUN_V1,
        "dataset": {
            "dataset_filename": dataset_path.name,
            "suite_name": context.suite_name,
            "content_digest_sha256": dataset_digest,
            "case_count": manifest.get("case_count") if manifest else None,
            "contract_id": manifest.get("contract_id") if manifest else None,
            "packaged_resource": manifest.get("packaged_resource") if manifest else None,
        },
        "runtime": {
            "llm_mode": context.llm_mode.value,
            "simulation_seed": context.simulation_seed,
            "deterministic": context.llm_mode == LLMMode.SIMULATION,
        },
        "code": {
            "package_version": context.package_version,
            "commit_sha": _resolved_code_commit_sha(context),
            "config_fingerprint_sha256": _resolved_config_fingerprint(context),
        },
        "metrics": {
            "definitions": _resolved_metric_definitions(context),
        },
    }
    validate_json_document(
        metadata,
        evaluation_run_provenance_schema(),
        label="run metadata",
    )
    return metadata


def assert_metadata_dataset_digest(metadata: Mapping[str, Any], dataset_path: Path) -> None:
    """Fail closed when embedded digest does not match dataset file bytes."""
    digest = metadata.get("dataset", {}).get("content_digest_sha256")
    expected = compute_dataset_digest(Path(dataset_path))
    if digest != expected:
        raise EvaluationContractError(
            "run metadata dataset digest does not match dataset file bytes"
        )
