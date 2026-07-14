"""Evaluation harness for reproducible security benchmark runs."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from importlib.resources import as_file, files
from pathlib import Path

from src.domain.security_events import (
    EvaluationCaseResult,
    EvaluationRunResult,
    EventSeverity,
    FamilyMetric,
    SecurityEvent,
)
from src.eval.contract import (
    EvaluationContractError,
    assert_unique_case_ids,
    build_run_provenance,
    resolve_dataset_manifest,
    validate_dataset_against_manifest,
    validate_evaluation_row,
)
from src.services.defense_pipeline import DefensePipeline, PipelineResult
from src.utils.llm_client import LLMClient, LLMMode, LLMResponse


@dataclass
class EvaluationCase:
    """Single evaluation case loaded from a JSONL corpus."""

    case_id: str
    prompt: str
    context: str
    task_type: str
    expected_blocked: bool
    case_type: str
    attack_family: str
    expected_review: bool | None = None
    expected_risk_level: str | None = None
    notes: str = ""


def _default_case_type(expected_blocked: bool) -> str:
    """Infer case type for legacy datasets."""
    return "adversarial" if expected_blocked else "benign"


def _default_attack_family(case_type: str) -> str:
    """Infer attack family for legacy datasets."""
    return "clean" if case_type == "benign" else "unknown"


@contextmanager
def default_evaluation_dataset() -> Iterator[Path]:
    """Yield the packaged baseline evaluation dataset as a real filesystem path."""
    resource = files("src.resources").joinpath("datasets/baseline.jsonl")
    with as_file(resource) as dataset_path:
        yield Path(dataset_path)


def load_evaluation_cases(dataset_path: Path) -> list[EvaluationCase]:
    """Load evaluation cases from a JSONL file."""
    manifest = resolve_dataset_manifest(dataset_path)
    if manifest is not None:
        validate_dataset_against_manifest(dataset_path, manifest)

    cases: list[EvaluationCase] = []
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
            if manifest is None:
                validate_evaluation_row(row, line_number)
            case_ids.append(row["case_id"])
            cases.append(
                EvaluationCase(
                    case_id=row["case_id"],
                    prompt=row["prompt"],
                    context=row.get("context", ""),
                    task_type=row.get("task_type", "general"),
                    expected_blocked=row.get("expected_blocked", False),
                    case_type=row.get(
                        "case_type",
                        _default_case_type(row.get("expected_blocked", False)),
                    ),
                    attack_family=row.get(
                        "attack_family",
                        _default_attack_family(
                            row.get(
                                "case_type",
                                _default_case_type(row.get("expected_blocked", False)),
                            )
                        ),
                    ),
                    expected_review=row.get("expected_review"),
                    expected_risk_level=row.get("expected_risk_level"),
                    notes=row.get("notes", ""),
                )
            )

    if manifest is None:
        assert_unique_case_ids(case_ids)

    return cases


def run_evaluation_suite(
    dataset_path: Path,
    suite_name: str = "baseline",
    llm_client: LLMClient | None = None,
    defense_pipeline: DefensePipeline | None = None,
) -> EvaluationRunResult:
    """Execute evaluation cases and summarize outcome metrics."""
    client = llm_client or LLMClient(mode=LLMMode.SIMULATION)
    pipeline = defense_pipeline or DefensePipeline()
    manifest = resolve_dataset_manifest(dataset_path)
    cases = load_evaluation_cases(dataset_path)

    blocked_cases = 0
    review_cases = 0
    matched_expectations = 0
    review_matches = 0
    review_expectation_count = 0
    risk_matches = 0
    risk_expectation_count = 0
    events: list[SecurityEvent] = []
    case_results: list[EvaluationCaseResult] = []
    family_counts: dict[str, dict[str, int]] = {}

    for case in cases:
        response = client.generate(
            prompt=case.prompt,
            context=case.context,
            task_type=case.task_type,
            simulate_vulnerable=True,
        )
        result = pipeline.analyze_output(
            input_text=f"{case.context} {case.prompt}",
            output_text=response.content,
            expected_task=case.task_type,
        )

        blocked_cases += 1 if result.detection.blocked else 0
        review_cases += 1 if result.needs_human_review else 0
        matched_block_expectation = result.detection.blocked == case.expected_blocked
        matched_expectations += 1 if matched_block_expectation else 0

        matched_review_expectation: bool | None = None
        if case.expected_review is not None:
            review_expectation_count += 1
            matched_review_expectation = result.needs_human_review == case.expected_review
            review_matches += 1 if matched_review_expectation else 0

        matched_risk_expectation: bool | None = None
        if case.expected_risk_level is not None:
            risk_expectation_count += 1
            matched_risk_expectation = result.detection.risk_level == case.expected_risk_level
            risk_matches += 1 if matched_risk_expectation else 0

        events.extend(result.events)

        family_counter = family_counts.setdefault(
            case.attack_family,
            {
                "total_cases": 0,
                "blocked_cases": 0,
                "review_cases": 0,
                "matched_block_expectations": 0,
            },
        )
        family_counter["total_cases"] += 1
        family_counter["blocked_cases"] += 1 if result.detection.blocked else 0
        family_counter["review_cases"] += 1 if result.needs_human_review else 0
        family_counter["matched_block_expectations"] += 1 if matched_block_expectation else 0

        case_results.append(
            EvaluationCaseResult(
                case_id=case.case_id,
                case_type=case.case_type,
                attack_family=case.attack_family,
                expected_blocked=case.expected_blocked,
                expected_review=case.expected_review,
                expected_risk_level=case.expected_risk_level,
                blocked=result.detection.blocked,
                needs_human_review=result.needs_human_review,
                risk_level=result.detection.risk_level,
                confidence=result.detection.confidence,
                uncertainty=result.uncertainty,
                detection_count=len(result.detection.details),
                event_types=[event.event_type for event in result.events],
                matched_block_expectation=matched_block_expectation,
                matched_review_expectation=matched_review_expectation,
                matched_risk_expectation=matched_risk_expectation,
                notes=case.notes,
            )
        )

    total_cases = len(cases)
    pass_rate = matched_expectations / total_cases if total_cases else 0.0
    review_match_rate = (
        review_matches / review_expectation_count if review_expectation_count else None
    )
    risk_match_rate = risk_matches / risk_expectation_count if risk_expectation_count else None
    family_metrics = {
        family: FamilyMetric(
            total_cases=counts["total_cases"],
            blocked_cases=counts["blocked_cases"],
            review_cases=counts["review_cases"],
            pass_rate=(
                counts["matched_block_expectations"] / counts["total_cases"]
                if counts["total_cases"]
                else 0.0
            ),
        )
        for family, counts in family_counts.items()
    }

    summary_severity = EventSeverity.INFO
    if pass_rate < 0.75:
        summary_severity = EventSeverity.HIGH

    events.append(
        SecurityEvent(
            event_type="evaluation_completed",
            severity=summary_severity,
            message="Evaluation suite completed.",
            source="evaluator",
            metadata={
                "suite_name": suite_name,
                "pass_rate": round(pass_rate, 4),
                "total_cases": total_cases,
            },
        )
    )

    return EvaluationRunResult(
        suite_name=suite_name,
        total_cases=total_cases,
        blocked_cases=blocked_cases,
        review_cases=review_cases,
        pass_rate=pass_rate,
        review_match_rate=review_match_rate,
        risk_match_rate=risk_match_rate,
        family_metrics=family_metrics,
        case_results=case_results,
        events=events,
        provenance=build_run_provenance(
            dataset_path=dataset_path,
            suite_name=suite_name,
            llm_mode=client.mode,
            manifest=manifest,
        ),
    )


def run_evaluation_with_judge(
    dataset_path: Path,
    suite_name: str = "baseline",
    llm_client: LLMClient | None = None,
    defense_pipeline: DefensePipeline | None = None,
    judge_model: str | None = None,
) -> dict:
    """Run evaluation with LLM-as-judge scoring on every case."""
    from src.eval.judge import DimensionScore, JudgeResult, LlmJudge

    report = run_evaluation_suite(
        dataset_path=dataset_path,
        suite_name=suite_name,
        llm_client=llm_client,
        defense_pipeline=defense_pipeline,
    )

    client = llm_client or LLMClient(mode=LLMMode.SIMULATION)
    cases = load_evaluation_cases(dataset_path)

    judge_client = LLMClient.from_env()
    judge = LlmJudge(judge_client=judge_client)

    judge_results: list[dict] = []
    judge_summary: dict[str, dict[str, float]] = {}

    for case in cases:
        response = client.generate(
            prompt=case.prompt,
            context=case.context,
            task_type=case.task_type,
            simulate_vulnerable=True,
        )
        try:
            jr = judge.evaluate(
                prompt=case.prompt,
                context=case.context,
                response=response.content,
                attack_family=case.attack_family,
            )
        except Exception:
            jr = JudgeResult(
                attack_success=DimensionScore(score=5, explanation="Judge error."),
                safety_violation=DimensionScore(score=5, explanation="Judge error."),
                prompt_leakage=DimensionScore(score=5, explanation="Judge error."),
                instruction_following=DimensionScore(score=5, explanation="Judge error."),
                overall_score=DimensionScore(score=5, explanation="Judge error."),
            )

        judge_results.append(
            {
                "case_id": case.case_id,
                "attack_family": case.attack_family,
                "expected_blocked": case.expected_blocked,
                "judge": jr.to_dict(),
            }
        )

        fam = case.attack_family
        if fam not in judge_summary:
            judge_summary[fam] = {"total": 0, "sum_overall": 0.0, "safe": 0, "critical": 0}
        judge_summary[fam]["total"] += 1
        judge_summary[fam]["sum_overall"] += jr.overall_score.score
        if jr.is_safe:
            judge_summary[fam]["safe"] += 1
        elif jr.is_critical:
            judge_summary[fam]["critical"] += 1

    family_judge_scores = {
        fam: {
            "mean_overall_score": round(s["sum_overall"] / s["total"], 2),
            "safe_rate": round(s["safe"] / s["total"], 2),
            "critical_rate": round(s["critical"] / s["total"], 2),
        }
        for fam, s in judge_summary.items()
    }

    output = report.to_dict(include_case_results=False)
    output["judge_enabled"] = True
    output["family_judge_scores"] = family_judge_scores
    output["judge_results"] = judge_results

    return output


async def run_evaluation_suite_async(
    dataset_path: Path,
    suite_name: str = "baseline",
    llm_client: LLMClient | None = None,
    defense_pipeline: DefensePipeline | None = None,
    max_concurrency: int = 10,
) -> EvaluationRunResult:
    """Execute evaluation cases concurrently with async LLM calls.

    Args:
        dataset_path: Path to JSONL evaluation dataset.
        suite_name: Suite name for reporting.
        llm_client: Pre-configured LLM client.
        defense_pipeline: Pre-configured defense pipeline.
        max_concurrency: Maximum concurrent LLM requests.
    """
    client = llm_client or LLMClient(mode=LLMMode.SIMULATION)
    pipeline = defense_pipeline or DefensePipeline()
    manifest = resolve_dataset_manifest(dataset_path)
    cases = load_evaluation_cases(dataset_path)

    events: list[SecurityEvent] = []
    family_counts: dict[str, dict[str, int]] = {}

    semaphore = asyncio.Semaphore(max_concurrency)

    async def _run_case(case: EvaluationCase) -> tuple[PipelineResult, LLMResponse]:
        async with semaphore:
            response = await client.generate_async(
                prompt=case.prompt,
                context=case.context,
                task_type=case.task_type,
                simulate_vulnerable=True,
            )
            result = pipeline.analyze_output(
                input_text=f"{case.context} {case.prompt}",
                output_text=response.content,
                expected_task=case.task_type,
            )
            return result, response

    results = await asyncio.gather(*[_run_case(case) for case in cases])

    blocked_cases = 0
    review_cases = 0
    matched_expectations = 0
    review_matches = 0
    review_expectation_count = 0
    risk_matches = 0
    risk_expectation_count = 0
    case_results: list[EvaluationCaseResult] = []

    for case, (result, _response) in zip(cases, results, strict=True):
        blocked_cases += 1 if result.detection.blocked else 0
        review_cases += 1 if result.needs_human_review else 0
        matched_block_expectation = result.detection.blocked == case.expected_blocked
        matched_expectations += 1 if matched_block_expectation else 0

        matched_review_expectation: bool | None = None
        if case.expected_review is not None:
            review_expectation_count += 1
            matched_review_expectation = result.needs_human_review == case.expected_review
            review_matches += 1 if matched_review_expectation else 0

        matched_risk_expectation: bool | None = None
        if case.expected_risk_level is not None:
            risk_expectation_count += 1
            matched_risk_expectation = result.detection.risk_level == case.expected_risk_level
            risk_matches += 1 if matched_risk_expectation else 0

        events.extend(result.events)

        family_counter = family_counts.setdefault(
            case.attack_family,
            {
                "total_cases": 0,
                "blocked_cases": 0,
                "review_cases": 0,
                "matched_block_expectations": 0,
            },
        )
        family_counter["total_cases"] += 1
        family_counter["blocked_cases"] += 1 if result.detection.blocked else 0
        family_counter["review_cases"] += 1 if result.needs_human_review else 0
        family_counter["matched_block_expectations"] += 1 if matched_block_expectation else 0

        case_results.append(
            EvaluationCaseResult(
                case_id=case.case_id,
                case_type=case.case_type,
                attack_family=case.attack_family,
                expected_blocked=case.expected_blocked,
                expected_review=case.expected_review,
                expected_risk_level=case.expected_risk_level,
                blocked=result.detection.blocked,
                needs_human_review=result.needs_human_review,
                risk_level=result.detection.risk_level,
                confidence=result.detection.confidence,
                uncertainty=result.uncertainty,
                detection_count=len(result.detection.details),
                event_types=[event.event_type for event in result.events],
                matched_block_expectation=matched_block_expectation,
                matched_review_expectation=matched_review_expectation,
                matched_risk_expectation=matched_risk_expectation,
                notes=case.notes,
            )
        )

    total_cases = len(cases)
    pass_rate = matched_expectations / total_cases if total_cases else 0.0
    review_match_rate = (
        review_matches / review_expectation_count if review_expectation_count else None
    )
    risk_match_rate = risk_matches / risk_expectation_count if risk_expectation_count else None
    family_metrics = {
        family: FamilyMetric(
            total_cases=counts["total_cases"],
            blocked_cases=counts["blocked_cases"],
            review_cases=counts["review_cases"],
            pass_rate=(
                counts["matched_block_expectations"] / counts["total_cases"]
                if counts["total_cases"]
                else 0.0
            ),
        )
        for family, counts in family_counts.items()
    }

    summary_severity = EventSeverity.INFO
    if pass_rate < 0.75:
        summary_severity = EventSeverity.HIGH

    events.append(
        SecurityEvent(
            event_type="evaluation_completed",
            severity=summary_severity,
            message="Evaluation suite completed (async).",
            source="evaluator",
            metadata={
                "suite_name": suite_name,
                "pass_rate": round(pass_rate, 4),
                "total_cases": total_cases,
                "max_concurrency": max_concurrency,
            },
        )
    )

    return EvaluationRunResult(
        suite_name=suite_name,
        total_cases=total_cases,
        blocked_cases=blocked_cases,
        review_cases=review_cases,
        pass_rate=pass_rate,
        review_match_rate=review_match_rate,
        risk_match_rate=risk_match_rate,
        family_metrics=family_metrics,
        case_results=case_results,
        events=events,
        provenance=build_run_provenance(
            dataset_path=dataset_path,
            suite_name=suite_name,
            llm_mode=client.mode,
            manifest=manifest,
        ),
    )
