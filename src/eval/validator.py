"""Dataset validation and run metadata generation for the evaluation contract."""

from __future__ import annotations

import json
from importlib.resources import as_file, files
from pathlib import Path
from typing import Any

from src.eval.contract import (
    EvaluationContractError,
    assert_unique_case_ids,
    baseline_manifest_path,
    build_run_provenance,
    compute_dataset_digest,
    evaluation_manifest_schema,
    evaluation_run_provenance_schema,
    load_dataset_manifest,
    resolve_dataset_manifest,
    validate_dataset_against_manifest,
    validate_evaluation_row,
    validate_json_document,
)
from src.utils.llm_client import LLMMode


def assert_packaged_resource_parity(manifest: dict[str, Any], dataset_path: Path) -> None:
    """Fail closed when the on-disk dataset diverges from the packaged resource."""
    packaged = manifest.get("packaged_resource")
    if not packaged:
        return
    if not isinstance(packaged, str) or not packaged.strip():
        return

    resource = files("src.resources").joinpath(packaged)
    try:
        with as_file(resource) as packaged_path:
            packaged_bytes = Path(packaged_path).read_bytes()
    except (FileNotFoundError, ModuleNotFoundError, TypeError) as exc:
        raise EvaluationContractError(
            f"packaged_resource {packaged!r} is not available in src.resources"
        ) from exc

    dataset_bytes = dataset_path.read_bytes()
    if packaged_bytes != dataset_bytes:
        raise EvaluationContractError(
            "source/package parity violation: dataset bytes do not match "
            f"packaged resource {packaged!r}"
        )


def _validate_rows_without_manifest(dataset_path: Path) -> list[str]:
    """Validate an ungoverned JSONL file (schema + unique ids only)."""
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
            validate_evaluation_row(row, line_number)
            case_ids.append(row["case_id"])
    assert_unique_case_ids(case_ids)
    return case_ids


def validate_dataset(
    dataset_path: Path,
    manifest: dict[str, Any] | None = None,
    *,
    check_packaged_parity: bool = True,
) -> dict[str, Any] | None:
    """
    Validate a JSONL evaluation dataset fail-closed against the frozen contract.

    When ``manifest`` is omitted, resolves a sibling ``.manifest.json`` or a
    packaged manifest whose digest matches the dataset bytes. Governed datasets
    are checked for unique ids, required labels, allowed families/types,
    canonical ordering, digest integrity, and optional source/package parity.
    """
    path = Path(dataset_path)
    resolved = manifest

    if resolved is None:
        sibling = baseline_manifest_path(path)
        if sibling is not None:
            resolved = load_dataset_manifest(sibling)
        else:
            resolved = resolve_dataset_manifest(path)

    if resolved is None:
        _validate_rows_without_manifest(path)
        return None

    validate_json_document(
        resolved,
        evaluation_manifest_schema(),
        label="manifest",
    )
    validate_dataset_against_manifest(path, resolved)
    if check_packaged_parity:
        assert_packaged_resource_parity(resolved, path)
    return resolved


def generate_run_metadata(
    *,
    dataset_path: Path,
    suite_name: str,
    llm_mode: LLMMode = LLMMode.SIMULATION,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Build and schema-validate run provenance (digest, code/config fingerprint, metrics).

    Default ``llm_mode`` is simulation so callers do not need live API credentials.
    """
    metadata = build_run_provenance(
        dataset_path=Path(dataset_path),
        suite_name=suite_name,
        llm_mode=llm_mode,
        manifest=manifest,
    )
    validate_json_document(
        metadata,
        evaluation_run_provenance_schema(),
        label="run metadata",
    )
    digest = metadata.get("dataset", {}).get("content_digest_sha256")
    if digest != compute_dataset_digest(Path(dataset_path)):
        raise EvaluationContractError(
            "run metadata dataset digest does not match dataset file bytes"
        )
    return metadata
