"""Service-layer helpers for defense orchestration and evaluation."""

from src.services.canonicalization import CanonicalizationResult, canonicalize_text
from src.services.defense_pipeline import DefensePipeline, PipelineResult
from src.services.evaluator import (
    EvaluationCase,
    default_evaluation_dataset,
    load_evaluation_cases,
    run_evaluation_suite,
    run_evaluation_suite_async,
    run_evaluation_with_judge,
)
from src.services.tracing import get_tracer, trace_span

__all__ = [
    "CanonicalizationResult",
    "DefensePipeline",
    "EvaluationCase",
    "PipelineResult",
    "canonicalize_text",
    "default_evaluation_dataset",
    "get_tracer",
    "load_evaluation_cases",
    "run_evaluation_suite",
    "run_evaluation_suite_async",
    "run_evaluation_with_judge",
    "trace_span",
]
