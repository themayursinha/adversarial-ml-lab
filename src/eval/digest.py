"""Deterministic digests and dataset manifest generation for the evaluation contract."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any, Mapping

from src.eval.contract import (
    CONTRACT_DATASET_V1,
    EVALUATION_CASE_SCHEMA_REF,
    MANIFEST_VERSION,
    EvaluationContractError,
    evaluation_manifest_schema,
    validate_json_document,
)

_DEFAULT_REQUIRED_FIELDS = [
    "case_id",
    "prompt",
    "context",
    "task_type",
    "expected_blocked",
    "case_type",
    "attack_family",
]
_DEFAULT_ALLOWED_CASE_TYPES = ["benign", "adversarial"]
_DEFAULT_ALLOWED_RISK_LEVELS = ["low", "medium", "high", "critical"]


def canonical_jsonl_line(row: Mapping[str, Any]) -> str:
    """Serialize one evaluation row for stable, order-independent hashing."""
    return json.dumps(dict(row), sort_keys=True, separators=(",", ":"))


def load_jsonl_rows(dataset_path: Path) -> list[dict[str, Any]]:
    """Parse a JSONL dataset into row dicts (file order, no blank lines)."""
    path = Path(dataset_path)
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                raise EvaluationContractError(
                    f"line {line_number}: empty line is not allowed"
                )
            try:
                row = json.loads(stripped)
            except json.JSONDecodeError as exc:
                raise EvaluationContractError(
                    f"line {line_number}: invalid JSON: {exc}"
                ) from exc
            if not isinstance(row, dict):
                raise EvaluationContractError(
                    f"line {line_number}: row must be a JSON object"
                )
            rows.append(row)
    return rows


def compute_dataset_file_digest(dataset_path: Path) -> str:
    """SHA-256 hex digest of raw on-disk JSONL bytes (frozen manifest contract)."""
    return hashlib.sha256(Path(dataset_path).read_bytes()).hexdigest()


def compute_sorted_jsonl_content_digest(dataset_path: Path) -> str:
    """
    SHA-256 hex digest of canonical JSONL lines sorted by ``case_id``.

    Rows are serialized with sorted keys and joined with newlines (no trailing
    newline). Useful for logical-content fingerprints; governed manifests still
    store ``compute_dataset_file_digest`` as ``content_digest_sha256``.
    """
    rows = load_jsonl_rows(dataset_path)
    if not rows:
        raise EvaluationContractError("dataset must contain at least one evaluation case")
    for index, row in enumerate(rows, start=1):
        if "case_id" not in row:
            raise EvaluationContractError(f"line {index}: missing case_id")
    canonical_lines = [
        canonical_jsonl_line(row)
        for row in sorted(rows, key=lambda item: item["case_id"])
    ]
    payload = "\n".join(canonical_lines).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def compute_config_digest(config_payload: Mapping[str, Any]) -> str:
    """SHA-256 hex digest of a JSON object with sorted keys (config fingerprint)."""
    canonical = json.dumps(config_payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_simulation_seed_digest(simulation_seed: None = None) -> str:
    """Deterministic digest for the v1 simulation seed (always JSON ``null``)."""
    if simulation_seed is not None:
        raise EvaluationContractError("simulation_seed digest is only defined for null in v1")
    canonical = json.dumps(None, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def build_dataset_manifest(
    dataset_path: Path,
    *,
    suite_name: str,
    packaged_resource: str | None = None,
    required_fields: list[str] | None = None,
    allowed_case_types: list[str] | None = None,
    allowed_risk_levels: list[str] | None = None,
    validate: bool = True,
) -> dict[str, Any]:
    """
    Build a dataset manifest dict from a JSONL file.

    ``content_digest_sha256`` uses file bytes. ``case_ids`` follow JSONL order;
    ``family_counts`` keys are sorted for stable JSON output.
    """
    path = Path(dataset_path)
    if not suite_name.strip():
        raise EvaluationContractError("suite_name must be a non-empty string")

    rows = load_jsonl_rows(path)
    if not rows:
        raise EvaluationContractError("dataset must contain at least one evaluation case")

    case_ids: list[str] = []
    families: Counter[str] = Counter()
    for index, row in enumerate(rows, start=1):
        case_id = row.get("case_id")
        if not isinstance(case_id, str) or not case_id:
            raise EvaluationContractError(f"line {index}: case_id must be a non-empty string")
        case_ids.append(case_id)
        family = row.get("attack_family") or "unknown"
        if not isinstance(family, str) or not family:
            family = "unknown"
        families[family] += 1

    manifest: dict[str, Any] = {
        "manifest_version": MANIFEST_VERSION,
        "contract_id": CONTRACT_DATASET_V1,
        "suite_name": suite_name,
        "dataset_filename": path.name,
        "content_digest_sha256": compute_dataset_file_digest(path),
        "case_count": len(case_ids),
        "case_ids": case_ids,
        "family_counts": dict(sorted(families.items())),
        "schema_ref": EVALUATION_CASE_SCHEMA_REF,
        "required_fields": list(required_fields or _DEFAULT_REQUIRED_FIELDS),
        "allowed_case_types": list(allowed_case_types or _DEFAULT_ALLOWED_CASE_TYPES),
        "allowed_risk_levels": list(allowed_risk_levels or _DEFAULT_ALLOWED_RISK_LEVELS),
    }
    if packaged_resource is not None:
        if not packaged_resource.strip():
            raise EvaluationContractError("packaged_resource must be non-empty when set")
        manifest = {
            **{
                k: manifest[k]
                for k in (
                    "manifest_version",
                    "contract_id",
                    "suite_name",
                    "dataset_filename",
                    "content_digest_sha256",
                    "case_count",
                    "case_ids",
                    "family_counts",
                )
            },
            "packaged_resource": packaged_resource,
            "schema_ref": manifest["schema_ref"],
            "required_fields": manifest["required_fields"],
            "allowed_case_types": manifest["allowed_case_types"],
            "allowed_risk_levels": manifest["allowed_risk_levels"],
        }

    if validate:
        validate_json_document(
            manifest,
            evaluation_manifest_schema(),
            label="generated manifest",
        )
    return manifest
