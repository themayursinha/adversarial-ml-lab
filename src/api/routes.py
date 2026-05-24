"""FastAPI route handlers for the adversarial ML lab."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from fastapi import APIRouter, HTTPException

from src.api.schemas import (
    EvalRequest,
    EvalResponse,
    HealthResponse,
    ScanRequest,
    ScanResponse,
)
from src.services import DefensePipeline, default_evaluation_dataset, run_evaluation_suite
from src.utils.llm_client import LLMClient

router = APIRouter()

_client: LLMClient | None = None
_pipeline: DefensePipeline | None = None


def _get_client() -> LLMClient:
    global _client
    if _client is None:
        _client = LLMClient.from_env()
    return _client


def _get_pipeline() -> DefensePipeline:
    global _pipeline
    if _pipeline is None:
        _pipeline = DefensePipeline()
    return _pipeline


@router.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    client = _get_client()
    return HealthResponse(
        status="ok",
        version="0.2.1",
        llm_mode=client.mode.value,
        model=client._client.model_name
        if hasattr(client._client, "model_name")
        else getattr(client._client, "model", "unknown"),
    )


@router.post("/scan", response_model=ScanResponse)
def scan(request: ScanRequest) -> ScanResponse:
    client = _get_client()
    pipeline = _get_pipeline()

    try:
        response = client.generate(
            prompt=request.prompt,
            context=request.content,
            task_type=request.task,
            simulate_vulnerable=request.simulate_vulnerable,
        )
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"LLM generation failed: {exc}") from exc

    result = pipeline.analyze_output(
        input_text=request.content,
        output_text=response.content,
        expected_task=request.task,
    )

    return ScanResponse(
        llm_mode=response.mode.value,
        model=response.model,
        tokens_used=response.tokens_used,
        latency_ms=response.latency_ms,
        risk_level=result.detection.risk_level,
        blocked=result.detection.blocked,
        confidence=result.detection.confidence,
        uncertainty=result.uncertainty,
        needs_human_review=result.needs_human_review,
        detections=result.detection.details,
        events=[event.to_dict() for event in result.events],
    )


@router.post("/eval", response_model=EvalResponse)
def run_eval(request: EvalRequest) -> EvalResponse:
    try:
        with _dataset_path(request.suite) as dataset:
            result = run_evaluation_suite(
                dataset_path=dataset,
                suite_name=request.suite,
                llm_client=_get_client(),
                defense_pipeline=_get_pipeline(),
            )
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Evaluation failed: {exc}") from exc

    return EvalResponse(
        suite_name=result.suite_name,
        total_cases=result.total_cases,
        blocked_cases=result.blocked_cases,
        review_cases=result.review_cases,
        pass_rate=result.pass_rate,
        review_match_rate=result.review_match_rate,
        risk_match_rate=result.risk_match_rate,
        family_metrics={name: fm.to_dict() for name, fm in result.family_metrics.items()},
        case_results=[cr.to_dict() for cr in result.case_results] if request.show_cases else None,
    )


@contextmanager
def _dataset_path(suite: str) -> Iterator[Path]:
    if suite == "baseline":
        with default_evaluation_dataset() as path:
            yield path
    else:
        dataset = Path("evals/datasets") / f"{suite}.jsonl"
        if not dataset.exists():
            raise FileNotFoundError(f"Dataset not found: {dataset}")
        yield dataset
