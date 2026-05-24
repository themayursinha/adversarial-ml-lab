"""Composable defense pipeline for output safety analysis."""

from __future__ import annotations

from dataclasses import dataclass, field

from src.defenses.anomaly_scorer import TextAnomalyScorer
from src.defenses.context_filter import ContextAwareFilter
from src.defenses.uncertainty_scorer import EnsembleUncertaintyScorer
from src.domain.security_events import (
    DetectionOutcome,
    EventSeverity,
    MitigationOutcome,
    SecurityEvent,
)
from src.services.canonicalization import canonicalize_text


@dataclass
class PipelineResult:
    """Combined output from canonicalization, filtering, and uncertainty scoring."""

    detection: DetectionOutcome
    mitigation: MitigationOutcome
    uncertainty: float
    needs_human_review: bool
    canonical_input: str
    canonical_output: str
    anomaly_score: dict | None = None
    events: list[SecurityEvent] = field(default_factory=list)


class DefensePipeline:
    """Pipeline that canonicalizes content and applies layered defenses."""

    def __init__(
        self,
        context_filter: ContextAwareFilter | None = None,
        uncertainty_scorer: EnsembleUncertaintyScorer | None = None,
        anomaly_scorer: TextAnomalyScorer | None = None,
    ) -> None:
        self.context_filter = context_filter or ContextAwareFilter(
            sensitivity=0.7, block_on_detection=True
        )
        self.uncertainty_scorer = uncertainty_scorer or EnsembleUncertaintyScorer(
            human_review_threshold=0.5
        )
        self.anomaly_scorer = anomaly_scorer or TextAnomalyScorer()

    def analyze_output(
        self,
        input_text: str,
        output_text: str,
        expected_task: str = "general",
    ) -> PipelineResult:
        """Run defense stages and return a normalized result object."""
        anomaly = self.anomaly_scorer.score(input_text)

        canonical_input_result = canonicalize_text(input_text)
        canonical_output_result = canonicalize_text(output_text)

        filter_result = self.context_filter.filter_output(
            canonical_output_result.canonical_text,
            input_context=canonical_input_result.canonical_text,
            expected_task=expected_task,
        )

        uncertainty_result = self.uncertainty_scorer.score(
            canonical_input_result.canonical_text,
            filter_result.filtered_output,
            context={"task_type": expected_task},
        )

        events: list[SecurityEvent] = []

        if anomaly.is_anomalous:
            events.append(
                SecurityEvent(
                    event_type="anomaly_detected",
                    severity=EventSeverity.MEDIUM,
                    message=anomaly.explanation,
                    source="anomaly_scorer",
                    metadata={
                        "overall_anomaly": anomaly.overall_anomaly,
                        "flags": ",".join(anomaly.flags) if anomaly.flags else "none",
                    },
                )
            )

        if canonical_input_result.removed_zero_width_count > 0:
            events.append(
                SecurityEvent(
                    event_type="canonicalization_applied",
                    severity=EventSeverity.MEDIUM,
                    message="Removed zero-width characters from input before analysis.",
                    source="canonicalization",
                    metadata={
                        "removed_zero_width": canonical_input_result.removed_zero_width_count,
                    },
                )
            )

        if filter_result.detections:
            severity = EventSeverity.HIGH
            if filter_result.risk_level.value == "critical":
                severity = EventSeverity.CRITICAL
            elif filter_result.risk_level.value in {"low", "medium"}:
                severity = EventSeverity.MEDIUM

            events.append(
                SecurityEvent(
                    event_type="attack_detected",
                    severity=severity,
                    message=filter_result.explanation,
                    source="context_filter",
                    metadata={
                        "risk_level": filter_result.risk_level.value,
                        "detection_count": len(filter_result.detections),
                    },
                )
            )

        if uncertainty_result.needs_human_review:
            events.append(
                SecurityEvent(
                    event_type="human_review_required",
                    severity=EventSeverity.HIGH,
                    message=uncertainty_result.recommendation,
                    source="uncertainty_scorer",
                    metadata={
                        "overall_uncertainty": round(uncertainty_result.overall_uncertainty, 4),
                    },
                )
            )

        detection = DetectionOutcome(
            blocked=filter_result.was_modified,
            risk_level=filter_result.risk_level.value,
            confidence=filter_result.confidence,
            details=filter_result.detections,
        )
        mitigation_reason = "output_blocked" if filter_result.was_modified else "output_allowed"
        mitigation = MitigationOutcome(
            output_text=filter_result.filtered_output,
            was_modified=filter_result.was_modified,
            reason=mitigation_reason,
        )

        return PipelineResult(
            detection=detection,
            mitigation=mitigation,
            uncertainty=uncertainty_result.overall_uncertainty,
            needs_human_review=uncertainty_result.needs_human_review,
            canonical_input=canonical_input_result.canonical_text,
            canonical_output=canonical_output_result.canonical_text,
            anomaly_score=anomaly.to_dict(),
            events=events,
        )
