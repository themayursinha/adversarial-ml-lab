"""Frozen evaluation dataset and run reproducibility contract."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, is_dataclass
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from omegaconf import OmegaConf

from src import __version__
from src.config.loader import get_default_config
from src.utils.llm_client import LLMMode

CONTRACT_DATASET_V1 = "adml.evaluation.dataset.v1"
CONTRACT_RUN_V1 = "adml.evaluation.run.v1"
CASE_ID_PATTERN = re.compile(r"^[a-z0-9_]+$")


class EvaluationContractError(ValueError):
    """Raised when a dataset or run violates the evaluation contract."""


def compute_dataset_digest(dataset_path: Path) -> str:
    """Return SHA-256 hex digest of the raw dataset file bytes."""
    return hashlib.sha256(dataset_path.read_bytes()).hexdigest()


def load_dataset_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load and parse a dataset manifest JSON file."""
    data: dict[str, Any] = json.loads(manifest_path.read_text(encoding="utf-8"))
    return data


def metric_definitions() -> dict[str, str]:
    """Immutable metric definitions included in run provenance."""
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


def _config_fingerprint() -> str:
    """Deterministic digest of default defense/LLM config used for eval runs."""
    config = get_default_config()
    if is_dataclass(config):
        payload = asdict(config)
    else:
        payload = OmegaConf.to_container(config, resolve=True)
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def baseline_manifest_path(dataset_path: Path) -> Path | None:
    """Return a sibling manifest path when present."""
    sibling = dataset_path.with_name(f"{dataset_path.stem}.manifest.json")
    if sibling.is_file():
        return sibling
    return None


def resolve_dataset_manifest(dataset_path: Path) -> dict[str, Any] | None:
    """Return a manifest when the dataset is governed by one."""
    manifest_path = baseline_manifest_path(dataset_path)
    if manifest_path is not None:
        return load_dataset_manifest(manifest_path)

    digest = compute_dataset_digest(dataset_path)
    resource = files("src.resources").joinpath("datasets/baseline.manifest.json")
    with as_file(resource) as packaged_manifest:
        manifest = load_dataset_manifest(Path(packaged_manifest))
    if manifest.get("content_digest_sha256") == digest:
        return manifest
    return None


def validate_evaluation_row(
    row: Any,
    line_number: int,
    *,
    required_fields: list[str] | None = None,
    allowed_case_types: list[str] | None = None,
    allowed_risk_levels: list[str] | None = None,
) -> None:
    """Validate a single JSONL row against evaluation_case.v1 rules."""
    if not isinstance(row, dict):
        raise EvaluationContractError(f"line {line_number}: row must be a JSON object")

    for field in ("case_id", "prompt", "context", "task_type", "expected_blocked"):
        if field not in row:
            raise EvaluationContractError(f"line {line_number}: missing required field '{field}'")

    case_id = row["case_id"]
    if not isinstance(case_id, str) or not case_id.strip():
        raise EvaluationContractError(f"line {line_number}: case_id must be a non-empty string")
    if not CASE_ID_PATTERN.match(case_id):
        raise EvaluationContractError(f"line {line_number}: invalid case_id '{case_id}'")

    if not isinstance(row["prompt"], str):
        raise EvaluationContractError(f"line {line_number}: prompt must be a string")
    if not isinstance(row["context"], str):
        raise EvaluationContractError(f"line {line_number}: context must be a string")
    if not isinstance(row["task_type"], str) or not row["task_type"].strip():
        raise EvaluationContractError(f"line {line_number}: task_type must be a non-empty string")
    if not isinstance(row["expected_blocked"], bool):
        raise EvaluationContractError(f"line {line_number}: expected_blocked must be a boolean")

    extra_keys = set(row) - {
        "case_id",
        "prompt",
        "context",
        "task_type",
        "expected_blocked",
        "case_type",
        "attack_family",
        "expected_review",
        "expected_risk_level",
        "notes",
    }
    if extra_keys:
        raise EvaluationContractError(
            f"line {line_number}: unknown fields {sorted(extra_keys)}"
        )

    if row.get("case_type") is not None and allowed_case_types:
        if row["case_type"] not in allowed_case_types:
            raise EvaluationContractError(
                f"line {line_number}: invalid case_type '{row['case_type']}'"
            )
    if row.get("expected_risk_level") is not None and allowed_risk_levels:
        if row["expected_risk_level"] not in allowed_risk_levels:
            raise EvaluationContractError(
                f"line {line_number}: invalid expected_risk_level '{row['expected_risk_level']}'"
            )
    if row.get("expected_review") is not None and not isinstance(row["expected_review"], bool):
        raise EvaluationContractError(f"line {line_number}: expected_review must be a boolean")

    if required_fields:
        for field in required_fields:
            if field not in row:
                raise EvaluationContractError(
                    f"line {line_number}: manifest requires field '{field}'"
                )


def validate_dataset_against_manifest(
    dataset_path: Path,
    manifest: dict[str, Any],
) -> None:
    """Fail closed when dataset bytes or rows diverge from manifest."""
    digest = compute_dataset_digest(dataset_path)
    expected_digest = manifest.get("content_digest_sha256")
    if expected_digest and digest != expected_digest:
        raise EvaluationContractError(
            f"dataset digest mismatch: expected {expected_digest}, got {digest}"
        )

    required_fields = list(manifest.get("required_fields") or [])
    allowed_case_types = list(manifest.get("allowed_case_types") or [])
    allowed_risk_levels = list(manifest.get("allowed_risk_levels") or [])

    case_ids: list[str] = []
    family_counts: dict[str, int] = {}

    with dataset_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                raise EvaluationContractError(f"line {line_number}: empty line is not allowed")
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise EvaluationContractError(
                    f"line {line_number}: invalid JSON: {exc}"
                ) from exc

            validate_evaluation_row(
                row,
                line_number,
                required_fields=required_fields or None,
                allowed_case_types=allowed_case_types or None,
                allowed_risk_levels=allowed_risk_levels or None,
            )
            case_ids.append(row["case_id"])
            family = row.get("attack_family") or "unknown"
            family_counts[family] = family_counts.get(family, 0) + 1

    if len(case_ids) != len(set(case_ids)):
        raise EvaluationContractError("duplicate case_id values in dataset")

    expected_ids = manifest.get("case_ids")
    if expected_ids is not None and case_ids != list(expected_ids):
        raise EvaluationContractError("case_id ordering does not match manifest")

    expected_count = manifest.get("case_count")
    if expected_count is not None and len(case_ids) != int(expected_count):
        raise EvaluationContractError(
            f"case_count mismatch: manifest {expected_count}, file {len(case_ids)}"
        )

    expected_families = manifest.get("family_counts")
    if expected_families is not None and family_counts != dict(expected_families):
        raise EvaluationContractError(
            f"family_counts mismatch: manifest {expected_families}, file {family_counts}"
        )


def build_run_provenance(
    *,
    dataset_path: Path,
    suite_name: str,
    llm_mode: LLMMode,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build deterministic run metadata attached to evaluation results."""
    manifest = manifest or resolve_dataset_manifest(dataset_path)
    dataset_block: dict[str, Any] = {
        "path": str(dataset_path),
        "suite_name": suite_name,
        "content_digest_sha256": compute_dataset_digest(dataset_path),
        "case_count": manifest.get("case_count") if manifest else None,
        "contract_id": manifest.get("contract_id") if manifest else None,
    }
    return {
        "contract_id": CONTRACT_RUN_V1,
        "dataset": dataset_block,
        "runtime": {
            "llm_mode": llm_mode.value,
            "simulation_seed": None,
            "deterministic": llm_mode == LLMMode.SIMULATION,
        },
        "code": {
            "package_version": __version__,
            "config_fingerprint_sha256": _config_fingerprint(),
        },
        "metrics": {
            "definitions": metric_definitions(),
        },
    }
