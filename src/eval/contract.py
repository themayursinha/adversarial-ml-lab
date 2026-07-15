"""Frozen evaluation dataset and run reproducibility contract."""

from __future__ import annotations

import json
import re
from functools import lru_cache
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from src.utils.llm_client import LLMMode

CONTRACT_DATASET_V1 = "adml.evaluation.dataset.v1"
CONTRACT_RUN_V1 = "adml.evaluation.run.v1"
EVALUATION_CASE_SCHEMA_REF = "evaluation_case.v1"
MANIFEST_VERSION = "1.0.0"
CASE_ID_PATTERN = re.compile(r"^[a-z0-9_]+$")
DIGEST_SHA256_PATTERN = re.compile(r"^[a-f0-9]{64}$")

MANIFEST_ALLOWED_KEYS = frozenset(
    {
        "manifest_version",
        "contract_id",
        "suite_name",
        "dataset_filename",
        "content_digest_sha256",
        "case_count",
        "case_ids",
        "family_counts",
        "packaged_resource",
        "schema_ref",
        "required_fields",
        "allowed_case_types",
        "allowed_risk_levels",
    }
)


class EvaluationContractError(ValueError):
    """Raised when a dataset or run violates the evaluation contract."""


def compute_dataset_digest(dataset_path: Path) -> str:
    """Return SHA-256 hex digest of the raw dataset file bytes."""
    from src.eval.digest import compute_dataset_file_digest

    return compute_dataset_file_digest(dataset_path)


def _load_packaged_schema(relative_path: str) -> dict[str, Any]:
    resource = files("src.resources").joinpath(relative_path)
    with as_file(resource) as schema_path:
        data = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise EvaluationContractError(f"{relative_path} must be a JSON object")
    return data


@lru_cache(maxsize=1)
def evaluation_case_schema() -> dict[str, Any]:
    """Load the packaged evaluation_case.v1 JSON Schema."""
    return _load_packaged_schema("schemas/evaluation_case.v1.json")


@lru_cache(maxsize=1)
def evaluation_manifest_schema() -> dict[str, Any]:
    """Load the packaged evaluation_manifest.v1 JSON Schema."""
    return _load_packaged_schema("schemas/evaluation_manifest.v1.json")


@lru_cache(maxsize=1)
def evaluation_run_provenance_schema() -> dict[str, Any]:
    """Load the packaged evaluation_run_provenance.v1 JSON Schema."""
    return _load_packaged_schema("schemas/evaluation_run_provenance.v1.json")


def validate_json_document(
    document: Any,
    schema: dict[str, Any],
    *,
    label: str,
) -> None:
    """Fail closed when a JSON document violates a packaged JSON Schema."""
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda err: list(err.path))
    if errors:
        first = errors[0]
        path = ".".join(str(part) for part in first.path)
        location = f"{label}." if not path else f"{label}.{path}: "
        raise EvaluationContractError(f"{location}schema violation: {first.message}") from None


def validate_row_matches_evaluation_schema(row: Any, line_number: int) -> None:
    """Validate a JSONL row against evaluation_case.v1.json at runtime."""
    if not isinstance(row, dict):
        raise EvaluationContractError(f"line {line_number}: row must be a JSON object")
    validator = Draft202012Validator(evaluation_case_schema())
    errors = sorted(validator.iter_errors(row), key=lambda err: list(err.path))
    if errors:
        first = errors[0]
        raise EvaluationContractError(
            f"line {line_number}: schema violation: {first.message}"
        ) from None


def assert_unique_case_ids(case_ids: list[str]) -> None:
    """Fail closed when duplicate case identifiers appear in a dataset."""
    if not case_ids:
        raise EvaluationContractError("dataset must contain at least one evaluation case")
    if len(case_ids) != len(set(case_ids)):
        raise EvaluationContractError("duplicate case_id values in dataset")


def validate_manifest_document(
    manifest: Any,
    *,
    dataset_path: Path,
    require_filename_match: bool = True,
) -> None:
    """Fail closed on malformed or tampered dataset manifest documents."""
    if not isinstance(manifest, dict):
        raise EvaluationContractError("manifest must be a JSON object")

    validate_json_document(
        manifest,
        evaluation_manifest_schema(),
        label="manifest",
    )

    unknown = set(manifest) - MANIFEST_ALLOWED_KEYS
    if unknown:
        raise EvaluationContractError(
            f"manifest has unknown fields {sorted(unknown)}"
        )

    if manifest.get("contract_id") != CONTRACT_DATASET_V1:
        raise EvaluationContractError(
            f"manifest contract_id must be {CONTRACT_DATASET_V1!r}"
        )
    if manifest.get("manifest_version") != MANIFEST_VERSION:
        raise EvaluationContractError(
            f"manifest manifest_version must be {MANIFEST_VERSION!r}"
        )
    if manifest.get("schema_ref") != EVALUATION_CASE_SCHEMA_REF:
        raise EvaluationContractError(
            f"manifest schema_ref must be {EVALUATION_CASE_SCHEMA_REF!r}"
        )

    suite_name = manifest.get("suite_name")
    if not isinstance(suite_name, str) or not suite_name.strip():
        raise EvaluationContractError("manifest suite_name must be a non-empty string")

    dataset_filename = manifest.get("dataset_filename")
    if not isinstance(dataset_filename, str) or not dataset_filename.strip():
        raise EvaluationContractError(
            "manifest dataset_filename must be a non-empty string"
        )
    if require_filename_match and dataset_filename != dataset_path.name:
        raise EvaluationContractError(
            f"manifest dataset_filename must be {dataset_path.name!r}, "
            f"got {dataset_filename!r}"
        )

    digest = manifest.get("content_digest_sha256")
    if not isinstance(digest, str) or not DIGEST_SHA256_PATTERN.fullmatch(digest):
        raise EvaluationContractError(
            "manifest content_digest_sha256 must be a 64-character lowercase hex string"
        )

    case_count = manifest.get("case_count")
    if not isinstance(case_count, int) or case_count < 1:
        raise EvaluationContractError("manifest case_count must be a positive integer")

    case_ids = manifest.get("case_ids")
    if not isinstance(case_ids, list):
        raise EvaluationContractError("manifest case_ids must be a list of strings")
    if len(case_ids) != case_count:
        raise EvaluationContractError(
            f"manifest case_ids length {len(case_ids)} != case_count {case_count}"
        )
    for case_id in case_ids:
        if not isinstance(case_id, str) or not CASE_ID_PATTERN.match(case_id):
            raise EvaluationContractError(f"manifest contains invalid case_id {case_id!r}")
    if len(case_ids) != len(set(case_ids)):
        raise EvaluationContractError("manifest case_ids must be unique")

    family_counts = manifest.get("family_counts")
    if not isinstance(family_counts, dict):
        raise EvaluationContractError("manifest family_counts must be an object")
    family_total = 0
    for family, count in family_counts.items():
        if not isinstance(family, str) or not family.strip():
            raise EvaluationContractError("manifest family_counts keys must be strings")
        if not isinstance(count, int) or count < 0:
            raise EvaluationContractError(
                "manifest family_counts values must be non-negative integers"
            )
        family_total += count
    if family_total != case_count:
        raise EvaluationContractError(
            f"manifest family_counts sum {family_total} != case_count {case_count}"
        )

    required_fields = manifest.get("required_fields")
    if not isinstance(required_fields, list) or not all(
        isinstance(field, str) for field in required_fields
    ):
        raise EvaluationContractError("manifest required_fields must be a list of strings")

    allowed_case_types = manifest.get("allowed_case_types")
    if not isinstance(allowed_case_types, list) or not all(
        isinstance(value, str) for value in allowed_case_types
    ):
        raise EvaluationContractError(
            "manifest allowed_case_types must be a list of strings"
        )

    allowed_risk_levels = manifest.get("allowed_risk_levels")
    if not isinstance(allowed_risk_levels, list) or not all(
        isinstance(value, str) for value in allowed_risk_levels
    ):
        raise EvaluationContractError(
            "manifest allowed_risk_levels must be a list of strings"
        )

    packaged_resource = manifest.get("packaged_resource")
    if packaged_resource is not None and (
        not isinstance(packaged_resource, str) or not packaged_resource.strip()
    ):
        raise EvaluationContractError(
            "manifest packaged_resource must be a non-empty string when set"
        )


def load_dataset_manifest(manifest_path: Path) -> dict[str, Any]:
    """Load and parse a dataset manifest JSON file."""
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise EvaluationContractError(f"invalid manifest JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise EvaluationContractError("manifest must be a JSON object")
    return data


def metric_definitions() -> dict[str, str]:
    """Immutable metric definitions included in run provenance."""
    from src.eval.metadata import frozen_metric_definitions

    return frozen_metric_definitions()


def _config_fingerprint() -> str:
    from src.eval.metadata import compute_config_fingerprint_sha256

    return compute_config_fingerprint_sha256()


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
        manifest = load_dataset_manifest(manifest_path)
        validate_manifest_document(manifest, dataset_path=dataset_path)
        return manifest

    digest = compute_dataset_digest(dataset_path)
    resource = files("src.resources").joinpath("datasets/baseline.manifest.json")
    with as_file(resource) as packaged_manifest:
        manifest = load_dataset_manifest(Path(packaged_manifest))
    validate_manifest_document(
        manifest,
        dataset_path=dataset_path,
        require_filename_match=False,
    )
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
    validate_row_matches_evaluation_schema(row, line_number)

    if row.get("case_type") is not None and allowed_case_types:
        if row["case_type"] not in allowed_case_types:
            raise EvaluationContractError(
                f"line {line_number}: invalid case_type '{row['case_type']}'"
            )
    if row.get("expected_risk_level") is not None and allowed_risk_levels:
        if row["expected_risk_level"] not in allowed_risk_levels:
            raise EvaluationContractError(
                f"line {line_number}: invalid expected_risk_level "
                f"'{row['expected_risk_level']}'"
            )

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
    validate_manifest_document(manifest, dataset_path=dataset_path)

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

    assert_unique_case_ids(case_ids)

    expected_ids = manifest.get("case_ids")
    if expected_ids is not None and case_ids != list(expected_ids):
        raise EvaluationContractError("case_id ordering does not match manifest")

    expected_count = manifest.get("case_count")
    if expected_count is not None and len(case_ids) != int(expected_count):
        raise EvaluationContractError(
            f"case_count mismatch: manifest {expected_count}, file {len(case_ids)}"
        )

    family_counts: dict[str, int] = {}
    with dataset_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            row = json.loads(stripped)
            family = row.get("attack_family") or "unknown"
            family_counts[family] = family_counts.get(family, 0) + 1

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
    from src.eval.metadata import RunContext, build_run_metadata

    context = RunContext.for_dataset(
        dataset_path=dataset_path,
        suite_name=suite_name,
        llm_mode=llm_mode,
        manifest=manifest,
    )
    return build_run_metadata(context)
