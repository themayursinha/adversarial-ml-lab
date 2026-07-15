"""Self-contained evaluation simulation pipeline (no external LLM API calls)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from src.eval.contract import (
    EvaluationContractError,
    evaluation_run_provenance_schema,
    validate_json_document,
)
from src.eval.validator import validate_dataset
from src.services.evaluator import run_evaluation_suite
from src.utils.llm_client import LLMClient, LLMMode

SIMULATION_PIPELINE_ID = "evaluation_simulation_v1"


def stable_simulation_snapshot(report: dict[str, Any]) -> dict[str, Any]:
    """
    Return a JSON-serializable copy of ``report`` with volatile event timestamps removed.

    Used for deterministic regression checks; live CLI output still includes timestamps.
    """
    snapshot: dict[str, Any] = json.loads(json.dumps(report))
    for event in snapshot.get("events", []):
        if isinstance(event, dict):
            event.pop("timestamp", None)
    return snapshot


def validate_simulation_report(report: dict[str, Any]) -> None:
    """
    Fail closed when a simulation report is missing required fields or provenance
    does not conform to ``evaluation_run_provenance.v1.json``.
    """
    if report.get("simulation") is not True:
        raise EvaluationContractError("simulation report must set simulation=true")
    if report.get("pipeline") != SIMULATION_PIPELINE_ID:
        raise EvaluationContractError(
            f"simulation report pipeline must be {SIMULATION_PIPELINE_ID!r}"
        )
    provenance = report.get("provenance")
    if not isinstance(provenance, dict):
        raise EvaluationContractError("simulation report missing provenance object")
    validate_json_document(
        provenance,
        evaluation_run_provenance_schema(),
        label="simulation provenance",
    )
    runtime = provenance.get("runtime", {})
    if runtime.get("llm_mode") != LLMMode.SIMULATION.value:
        raise EvaluationContractError(
            "simulation provenance must record llm_mode='simulation'"
        )
    if runtime.get("deterministic") is not True:
        raise EvaluationContractError("simulation provenance must set deterministic=true")


def _simulation_llm_client() -> LLMClient:
    """Construct an LLM client that never auto-detects a live API backend."""
    return LLMClient(mode=LLMMode.SIMULATION)


def run_simulation_evaluation(
    dataset_path: Path,
    *,
    suite_name: str | None = None,
    check_packaged_parity: bool = True,
    include_case_results: bool = False,
) -> dict[str, Any]:
    """
    Validate the dataset, run the heuristic evaluation harness in simulation mode,
    and return a schema-checked report dict.

    No network access is required; callers must not pass ``LLMClient.from_env()``.
    """
    path = Path(dataset_path)
    manifest = validate_dataset(
        path,
        check_packaged_parity=check_packaged_parity,
    )
    resolved_suite = suite_name
    if resolved_suite is None:
        if manifest is not None:
            resolved_suite = str(manifest.get("suite_name") or "baseline")
        else:
            resolved_suite = path.stem

    client = _simulation_llm_client()
    result = run_evaluation_suite(
        dataset_path=path,
        suite_name=resolved_suite,
        llm_client=client,
    )
    if client.mode != LLMMode.SIMULATION:
        raise EvaluationContractError("simulation pipeline must use LLMMode.SIMULATION")

    report = result.to_dict(include_case_results=include_case_results)
    report["simulation"] = True
    report["pipeline"] = SIMULATION_PIPELINE_ID
    validate_simulation_report(report)
    return report
