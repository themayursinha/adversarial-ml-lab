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
    events: list[SecurityEvent] = field(default_factory=list)

    def to_dict(self) -> dict:
        """Return a JSON-serializable dictionary."""
        return {
            "suite_name": self.suite_name,
            "total_cases": self.total_cases,
            "blocked_cases": self.blocked_cases,
            "review_cases": self.review_cases,
            "pass_rate": self.pass_rate,
            "events": [event.to_dict() for event in self.events],
        }
