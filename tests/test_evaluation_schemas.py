"""JSON Schema acceptance tests for the evaluation contract (dataset / run / result)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from src.eval.contract import (
    EvaluationContractError,
    build_run_provenance,
    evaluation_case_schema,
    evaluation_manifest_schema,
    evaluation_run_provenance_schema,
    load_dataset_manifest,
    validate_json_document,
)
from src.utils.llm_client import LLMMode

REPO_ROOT = Path(__file__).resolve().parents[1]
BASELINE_JSONL = REPO_ROOT / "evals/datasets/baseline.jsonl"
BASELINE_MANIFEST = REPO_ROOT / "evals/datasets/baseline.manifest.json"
SCHEMA_BUNDLE = REPO_ROOT / "src/resources/schemas/schema.json"


def _first_schema_error(document: Any, schema: dict) -> str | None:
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(document), key=lambda err: list(err.path))
    if not errors:
        return None
    return errors[0].message


@pytest.mark.parametrize(
    "schema_loader",
    [
        evaluation_case_schema,
        evaluation_manifest_schema,
        evaluation_run_provenance_schema,
    ],
)
def test_packaged_schemas_are_valid_json_schema_documents(schema_loader) -> None:
    schema = schema_loader()
    Draft202012Validator.check_schema(schema)


def test_schema_json_umbrella_is_valid_and_resolves_refs() -> None:
    bundle = json.loads(SCHEMA_BUNDLE.read_text(encoding="utf-8"))
    Draft202012Validator.check_schema(bundle)
    assert bundle["oneOf"][0]["$ref"] == "evaluation_case.v1.json"
    assert bundle["oneOf"][1]["$ref"] == "evaluation_manifest.v1.json"
    assert bundle["oneOf"][2]["$ref"] == "evaluation_run_provenance.v1.json"


def test_evaluation_case_schema_accepts_baseline_row() -> None:
    row = json.loads(BASELINE_JSONL.read_text(encoding="utf-8").splitlines()[0])
    assert _first_schema_error(row, evaluation_case_schema()) is None


def test_evaluation_case_schema_rejects_invalid_row() -> None:
    invalid = {
        "case_id": "bad id",
        "prompt": "p",
        "context": "",
        "task_type": "chat",
        "expected_blocked": False,
    }
    message = _first_schema_error(invalid, evaluation_case_schema())
    assert message is not None


def test_evaluation_manifest_schema_accepts_baseline_manifest() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    assert _first_schema_error(manifest, evaluation_manifest_schema()) is None


def test_evaluation_manifest_schema_rejects_unknown_property() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    tampered = dict(manifest)
    tampered["extra_field"] = "not allowed"
    message = _first_schema_error(tampered, evaluation_manifest_schema())
    assert message is not None


def test_evaluation_manifest_schema_rejects_boolean_case_count() -> None:
    manifest = load_dataset_manifest(BASELINE_MANIFEST)
    tampered = dict(manifest)
    tampered["case_count"] = True
    message = _first_schema_error(tampered, evaluation_manifest_schema())
    assert message is not None


def test_evaluation_run_provenance_schema_accepts_baseline_run() -> None:
    provenance = build_run_provenance(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    assert _first_schema_error(provenance, evaluation_run_provenance_schema()) is None


def test_evaluation_run_provenance_schema_rejects_bad_digest() -> None:
    provenance = build_run_provenance(
        dataset_path=BASELINE_JSONL,
        suite_name="baseline",
        llm_mode=LLMMode.SIMULATION,
    )
    tampered = json.loads(json.dumps(provenance))
    tampered["dataset"]["content_digest_sha256"] = "not-a-digest"
    message = _first_schema_error(tampered, evaluation_run_provenance_schema())
    assert message is not None


def test_validate_json_document_surfaces_schema_violations() -> None:
    with pytest.raises(EvaluationContractError, match="schema violation"):
        validate_json_document(
            {"case_id": "x"},
            evaluation_case_schema(),
            label="case row",
        )
