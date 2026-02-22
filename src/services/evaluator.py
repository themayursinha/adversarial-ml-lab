"""Evaluation harness for reproducible security benchmark runs."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from src.domain.security_events import EvaluationRunResult, EventSeverity, SecurityEvent
from src.services.defense_pipeline import DefensePipeline
from src.utils.llm_client import LLMClient, LLMMode


@dataclass
class EvaluationCase:
    """Single evaluation case loaded from a JSONL corpus."""

    case_id: str
    prompt: str
    context: str
    task_type: str
    expected_blocked: bool


def load_evaluation_cases(dataset_path: Path) -> list[EvaluationCase]:
    """Load evaluation cases from a JSONL file."""
    cases: list[EvaluationCase] = []

    with dataset_path.open("r", encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            cases.append(
                EvaluationCase(
                    case_id=row["case_id"],
                    prompt=row["prompt"],
                    context=row.get("context", ""),
                    task_type=row.get("task_type", "general"),
                    expected_blocked=row.get("expected_blocked", False),
                )
            )

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
    cases = load_evaluation_cases(dataset_path)

    blocked_cases = 0
    review_cases = 0
    matched_expectations = 0
    events: list[SecurityEvent] = []

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
        matched_expectations += 1 if result.detection.blocked == case.expected_blocked else 0
        events.extend(result.events)

    total_cases = len(cases)
    pass_rate = matched_expectations / total_cases if total_cases else 0.0

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
        events=events,
    )
