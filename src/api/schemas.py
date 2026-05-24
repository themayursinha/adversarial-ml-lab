"""Pydantic schemas for the API request and response models."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    """Request for the /scan endpoint."""

    content: str = Field(..., description="Text content to scan for adversarial inputs.")
    prompt: str = Field(
        default="Please summarize this document.",
        description="Prompt used for model output generation.",
    )
    task: str = Field(
        default="summarize",
        pattern=r"^(general|summarize|classify|chat|qa)$",
        description="Expected task type for policy checks.",
    )
    simulate_vulnerable: bool = Field(
        default=True,
        description="Whether to simulate vulnerable model behavior.",
    )


class Detection(BaseModel):
    type: str
    description: str
    severity: str
    confidence: float | None = None


class SecurityEventResponse(BaseModel):
    event_type: str
    severity: str
    message: str
    source: str
    timestamp: str
    metadata: dict | None = None


class ScanResponse(BaseModel):
    llm_mode: str
    model: str
    tokens_used: int
    latency_ms: float
    risk_level: str
    blocked: bool
    confidence: float
    uncertainty: float
    needs_human_review: bool
    detections: list[dict] = []
    events: list[dict] = []


class EvalRequest(BaseModel):
    """Request for the /eval endpoint."""

    suite: str = Field(default="baseline", description="Evaluation suite name.")
    show_cases: bool = Field(default=False, description="Include per-case results in output.")
    max_concurrency: int = Field(default=10, ge=1, le=50, description="Max concurrent LLM calls.")


class FamilyMetricResponse(BaseModel):
    total_cases: int
    blocked_cases: int
    review_cases: int
    pass_rate: float


class EvalResponse(BaseModel):
    suite_name: str
    total_cases: int
    blocked_cases: int
    review_cases: int
    pass_rate: float
    review_match_rate: float | None = None
    risk_match_rate: float | None = None
    family_metrics: dict = {}
    case_results: list[dict] | None = None


class HealthResponse(BaseModel):
    status: str
    version: str
    llm_mode: str
    model: str


class ErrorResponse(BaseModel):
    detail: str
