"""Typed domain models for security analysis and evaluation outputs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum


class EventSeverity(Enum):
    """Event severity levels for detections and mitigations."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class SecurityEvent:
    """A structured security event emitted by the pipeline."""

    event_type: str
    severity: EventSeverity
    message: str
    source: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, str | int | float | bool] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary."""
        data = asdict(self)
        data["severity"] = self.severity.value
        return data


@dataclass
class DetectionOutcome:
    """Normalized output from detection stages."""

    blocked: bool
    risk_level: str
    confidence: float
    details: list[dict]


@dataclass
class MitigationOutcome:
    """Result of applying mitigation logic."""

    output_text: str
    was_modified: bool
    reason: str


@dataclass
class EvaluationRunResult:
    """Summary metrics for an evaluation run."""

    suite_name: str
    total_cases: int
    blocked_cases: int
    review_cases: int
    pass_rate: float
    review_match_rate: float | None = None
    risk_match_rate: float | None = None
    family_metrics: dict[str, "FamilyMetric"] = field(default_factory=dict)
    case_results: list["EvaluationCaseResult"] = field(default_factory=list)
    events: list[SecurityEvent] = field(default_factory=list)

    def to_dict(self, include_case_results: bool = False) -> dict:
        """Return a JSON-serializable dictionary."""
        payload = {
            "suite_name": self.suite_name,
            "total_cases": self.total_cases,
            "blocked_cases": self.blocked_cases,
            "review_cases": self.review_cases,
            "pass_rate": self.pass_rate,
            "review_match_rate": self.review_match_rate,
            "risk_match_rate": self.risk_match_rate,
            "family_metrics": {
                name: metric.to_dict() for name, metric in self.family_metrics.items()
            },
            "events": [event.to_dict() for event in self.events],
        }
        if include_case_results:
            payload["case_results"] = [result.to_dict() for result in self.case_results]
        return payload


@dataclass
class FamilyMetric:
    """Per-family evaluation aggregate metrics."""

    total_cases: int
    blocked_cases: int
    review_cases: int
    pass_rate: float

    def to_dict(self) -> dict[str, int | float]:
        """Return a JSON-serializable dictionary."""
        return {
            "total_cases": self.total_cases,
            "blocked_cases": self.blocked_cases,
            "review_cases": self.review_cases,
            "pass_rate": self.pass_rate,
        }


@dataclass
class EvaluationCaseResult:
    """Observed outcome for one evaluation case."""

    case_id: str
    case_type: str
    attack_family: str
    expected_blocked: bool
    expected_review: bool | None
    expected_risk_level: str | None
    blocked: bool
    needs_human_review: bool
    risk_level: str
    confidence: float
    uncertainty: float
    detection_count: int
    event_types: list[str]
    matched_block_expectation: bool
    matched_review_expectation: bool | None = None
    matched_risk_expectation: bool | None = None
    notes: str = ""

    def to_dict(self) -> dict[str, str | int | float | bool | None | list[str]]:
        """Return a JSON-serializable dictionary."""
        return {
            "case_id": self.case_id,
            "case_type": self.case_type,
            "attack_family": self.attack_family,
            "expected_blocked": self.expected_blocked,
            "expected_review": self.expected_review,
            "expected_risk_level": self.expected_risk_level,
            "blocked": self.blocked,
            "needs_human_review": self.needs_human_review,
            "risk_level": self.risk_level,
            "confidence": self.confidence,
            "uncertainty": self.uncertainty,
            "detection_count": self.detection_count,
            "event_types": self.event_types,
            "matched_block_expectation": self.matched_block_expectation,
            "matched_review_expectation": self.matched_review_expectation,
            "matched_risk_expectation": self.matched_risk_expectation,
            "notes": self.notes,
        }
