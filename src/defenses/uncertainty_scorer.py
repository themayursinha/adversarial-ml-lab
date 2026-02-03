"""
Ensemble Uncertainty Scoring
============================
Defense mechanism for human-in-the-loop decision making.

This module provides uncertainty quantification for LLM outputs by using
multiple analysis approaches to detect when the model's output may be
unreliable or manipulated. High uncertainty triggers human review.

SECURITY: Implements the "verify before trust" principle.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional, Callable
from enum import Enum
import re
import statistics


class ConfidenceLevel(Enum):
    """Confidence level for human review decisions."""
    HIGH = "high"  # No review needed
    MEDIUM = "medium"  # Optional review
    LOW = "low"  # Review recommended
    CRITICAL = "critical"  # Review required


@dataclass
class UncertaintySignal:
    """A single uncertainty signal from one analyzer."""
    analyzer_name: str
    raw_score: float  # 0.0 = certain, 1.0 = very uncertain
    normalized_score: float
    explanation: str
    metadata: dict = field(default_factory=dict)


@dataclass
class EnsembleResult:
    """Aggregated result from ensemble uncertainty scoring."""
    overall_uncertainty: float  # 0.0 to 1.0
    confidence_level: ConfidenceLevel
    needs_human_review: bool
    signals: list[UncertaintySignal]
    aggregation_method: str
    recommendation: str
    review_reasons: list[str]


class UncertaintyAnalyzer:
    """Base class for uncertainty analyzers."""
    
    name: str = "base"
    weight: float = 1.0
    
    def analyze(
        self,
        input_text: str,
        output_text: str,
        context: Optional[dict] = None,
    ) -> UncertaintySignal:
        """Analyze and return uncertainty signal."""
        raise NotImplementedError


class LengthRatioAnalyzer(UncertaintyAnalyzer):
    """Analyzes input/output length ratios for anomalies."""
    
    name = "length_ratio"
    weight = 0.8
    
    def __init__(
        self,
        expected_ratio_min: float = 0.1,
        expected_ratio_max: float = 3.0,
    ) -> None:
        """Initialize with expected ratio bounds."""
        self.min_ratio = expected_ratio_min
        self.max_ratio = expected_ratio_max
    
    def analyze(
        self,
        input_text: str,
        output_text: str,
        context: Optional[dict] = None,
    ) -> UncertaintySignal:
        """Analyze length ratio for anomalies."""
        input_len = len(input_text.split())
        output_len = len(output_text.split())
        
        if input_len == 0:
            ratio = float('inf')
        else:
            ratio = output_len / input_len
        
        # Calculate uncertainty based on deviation from expected range
        if self.min_ratio <= ratio <= self.max_ratio:
            raw_score = 0.0
            explanation = "Output length is within expected range"
        elif ratio < self.min_ratio:
            deviation = (self.min_ratio - ratio) / self.min_ratio
            raw_score = min(1.0, deviation)
            explanation = f"Output suspiciously short (ratio: {ratio:.2f})"
        else:
            deviation = (ratio - self.max_ratio) / self.max_ratio
            raw_score = min(1.0, deviation * 0.5)  # Less severe for long outputs
            explanation = f"Output unusually long (ratio: {ratio:.2f})"
        
        return UncertaintySignal(
            analyzer_name=self.name,
            raw_score=raw_score,
            normalized_score=raw_score * self.weight,
            explanation=explanation,
            metadata={"ratio": ratio, "input_words": input_len, "output_words": output_len},
        )


class PatternDeviationAnalyzer(UncertaintyAnalyzer):
    """Analyzes output for suspicious patterns."""
    
    name = "pattern_deviation"
    weight = 1.2
    
    # Patterns that indicate potential issues
    SUSPICIOUS_PATTERNS = [
        (r"(?i)i (cannot|can't|won't|will not|refuse)", 0.3, "refusal_detected"),
        (r"(?i)(error|exception|failed|failure)", 0.4, "error_indicator"),
        (r"(?i)(hack|attack|inject|exploit)", 0.6, "security_term"),
        (r"(?i)(ignore|bypass|override).{0,30}(instruction|rule|guideline)", 0.8, "bypass_language"),
        (r"(?i)admin|root|sudo|privilege", 0.5, "privilege_term"),
        (r"\[.*REDACTED.*\]", 0.4, "redaction_marker"),
        (r"(?i)(warning|alert|danger|critical)", 0.3, "warning_language"),
    ]
    
    def analyze(
        self,
        input_text: str,
        output_text: str,
        context: Optional[dict] = None,
    ) -> UncertaintySignal:
        """Analyze for suspicious patterns."""
        scores = []
        found_patterns = []
        
        for pattern, score, name in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, output_text):
                scores.append(score)
                found_patterns.append(name)
        
        if scores:
            raw_score = max(scores)  # Take highest concern
            explanation = f"Suspicious patterns detected: {', '.join(found_patterns)}"
        else:
            raw_score = 0.0
            explanation = "No suspicious patterns detected"
        
        return UncertaintySignal(
            analyzer_name=self.name,
            raw_score=raw_score,
            normalized_score=raw_score * self.weight,
            explanation=explanation,
            metadata={"patterns_found": found_patterns},
        )


class SemanticConsistencyAnalyzer(UncertaintyAnalyzer):
    """Analyzes semantic consistency between input task and output."""
    
    name = "semantic_consistency"
    weight = 1.0
    
    # Keywords expected for different task types
    TASK_KEYWORDS = {
        "summarize": ["summary", "key", "main", "points", "overview", "brief"],
        "classify": ["category", "class", "type", "classification", "label"],
        "answer": ["answer", "response", "solution", "result"],
        "explain": ["because", "reason", "explanation", "means", "refers"],
        "translate": ["translation", "translates"],
        "code": ["function", "def", "class", "return", "import", "```"],
    }
    
    def analyze(
        self,
        input_text: str,
        output_text: str,
        context: Optional[dict] = None,
    ) -> UncertaintySignal:
        """Analyze semantic consistency."""
        task_type = (context or {}).get("task_type", "general")
        expected_keywords = self.TASK_KEYWORDS.get(task_type, [])
        
        if not expected_keywords:
            return UncertaintySignal(
                analyzer_name=self.name,
                raw_score=0.2,  # Slight uncertainty for unknown task
                normalized_score=0.2 * self.weight,
                explanation="Unknown task type, cannot verify consistency",
                metadata={"task_type": task_type},
            )
        
        output_lower = output_text.lower()
        matches = sum(1 for kw in expected_keywords if kw in output_lower)
        match_ratio = matches / len(expected_keywords)
        
        raw_score = 1.0 - match_ratio
        
        if match_ratio >= 0.3:
            explanation = f"Output consistent with '{task_type}' task"
        else:
            explanation = f"Output may not match expected '{task_type}' format"
        
        return UncertaintySignal(
            analyzer_name=self.name,
            raw_score=raw_score,
            normalized_score=raw_score * self.weight,
            explanation=explanation,
            metadata={"task_type": task_type, "match_ratio": match_ratio},
        )


class ResponseCoherenceAnalyzer(UncertaintyAnalyzer):
    """Analyzes response coherence and structure."""
    
    name = "response_coherence"
    weight = 0.9
    
    def analyze(
        self,
        input_text: str,
        output_text: str,
        context: Optional[dict] = None,
    ) -> UncertaintySignal:
        """Analyze response coherence."""
        issues = []
        raw_score = 0.0
        
        # Check for abrupt endings
        if output_text.strip().endswith(('...', '…')) and len(output_text) > 50:
            issues.append("truncated_output")
            raw_score += 0.3
        
        # Check for mixed messages (e.g., both refusal and compliance)
        has_refusal = bool(re.search(r"(?i)cannot|can't|won't|unable", output_text))
        has_compliance = bool(re.search(r"(?i)here('s| is)|certainly|sure|okay", output_text))
        if has_refusal and has_compliance:
            issues.append("mixed_signals")
            raw_score += 0.4
        
        # Check for repeated content
        words = output_text.split()
        if len(words) > 10:
            # Simple repetition check
            window_size = 5
            for i in range(len(words) - window_size * 2):
                window = ' '.join(words[i:i+window_size])
                rest = ' '.join(words[i+window_size:])
                if window in rest:
                    issues.append("repetition_detected")
                    raw_score += 0.3
                    break
        
        raw_score = min(1.0, raw_score)
        
        if issues:
            explanation = f"Coherence issues: {', '.join(issues)}"
        else:
            explanation = "Response appears coherent"
        
        return UncertaintySignal(
            analyzer_name=self.name,
            raw_score=raw_score,
            normalized_score=raw_score * self.weight,
            explanation=explanation,
            metadata={"issues": issues},
        )


class EnsembleUncertaintyScorer:
    """
    Ensemble-based uncertainty scoring for human-in-the-loop decisions.
    
    Combines multiple analyzers to provide robust uncertainty estimates.
    High uncertainty triggers human review recommendations.
    """
    
    def __init__(
        self,
        analyzers: Optional[list[UncertaintyAnalyzer]] = None,
        human_review_threshold: float = 0.5,
        aggregation: str = "weighted_mean",
    ) -> None:
        """
        Initialize the ensemble scorer.
        
        Args:
            analyzers: List of analyzers to use
            human_review_threshold: Uncertainty threshold for requiring review
            aggregation: How to aggregate scores (weighted_mean, max, median)
        """
        self.analyzers = analyzers or [
            LengthRatioAnalyzer(),
            PatternDeviationAnalyzer(),
            SemanticConsistencyAnalyzer(),
            ResponseCoherenceAnalyzer(),
        ]
        self.human_review_threshold = human_review_threshold
        self.aggregation = aggregation
    
    def score(
        self,
        input_text: str,
        output_text: str,
        context: Optional[dict] = None,
    ) -> EnsembleResult:
        """
        Score the uncertainty of an LLM output.
        
        Args:
            input_text: Original input
            output_text: LLM output
            context: Optional context (task type, etc.)
            
        Returns:
            EnsembleResult with uncertainty analysis
        """
        # Collect signals from all analyzers
        signals = []
        for analyzer in self.analyzers:
            try:
                signal = analyzer.analyze(input_text, output_text, context)
                signals.append(signal)
            except Exception as e:
                # Don't let one analyzer failure stop the process
                signals.append(UncertaintySignal(
                    analyzer_name=analyzer.name,
                    raw_score=0.5,  # Default uncertainty on error
                    normalized_score=0.5,
                    explanation=f"Analyzer error: {str(e)}",
                ))
        
        # Aggregate scores
        if self.aggregation == "weighted_mean":
            total_weight = sum(a.weight for a in self.analyzers)
            overall = sum(s.normalized_score for s in signals) / total_weight
        elif self.aggregation == "max":
            overall = max(s.raw_score for s in signals)
        elif self.aggregation == "median":
            overall = statistics.median(s.raw_score for s in signals)
        else:
            overall = statistics.mean(s.raw_score for s in signals)
        
        overall = min(1.0, max(0.0, overall))
        
        # Determine confidence level
        if overall < 0.2:
            confidence_level = ConfidenceLevel.HIGH
        elif overall < 0.4:
            confidence_level = ConfidenceLevel.MEDIUM
        elif overall < 0.6:
            confidence_level = ConfidenceLevel.LOW
        else:
            confidence_level = ConfidenceLevel.CRITICAL
        
        # Determine if human review is needed
        needs_review = overall >= self.human_review_threshold
        
        # Collect review reasons
        review_reasons = [
            s.explanation
            for s in signals
            if s.raw_score >= 0.4
        ]
        
        # Generate recommendation
        if confidence_level == ConfidenceLevel.HIGH:
            recommendation = "Output appears reliable. No action needed."
        elif confidence_level == ConfidenceLevel.MEDIUM:
            recommendation = "Minor concerns detected. Optional human review."
        elif confidence_level == ConfidenceLevel.LOW:
            recommendation = "Significant uncertainty. Human review recommended."
        else:
            recommendation = "⚠️ CRITICAL: High uncertainty detected. Human review REQUIRED before use."
        
        return EnsembleResult(
            overall_uncertainty=overall,
            confidence_level=confidence_level,
            needs_human_review=needs_review,
            signals=signals,
            aggregation_method=self.aggregation,
            recommendation=recommendation,
            review_reasons=review_reasons,
        )
    
    def create_review_report(self, result: EnsembleResult) -> str:
        """Create a human-readable review report."""
        report = []
        report.append("=" * 60)
        report.append("UNCERTAINTY ANALYSIS REPORT")
        report.append("=" * 60)
        report.append("")
        report.append(f"Overall Uncertainty: {result.overall_uncertainty:.2%}")
        report.append(f"Confidence Level: {result.confidence_level.value.upper()}")
        report.append(f"Human Review Required: {'YES' if result.needs_human_review else 'No'}")
        report.append("")
        report.append("-" * 60)
        report.append("ANALYZER RESULTS")
        report.append("-" * 60)
        
        for signal in result.signals:
            report.append(f"\n{signal.analyzer_name}:")
            report.append(f"  Score: {signal.raw_score:.2%}")
            report.append(f"  {signal.explanation}")
        
        report.append("")
        report.append("-" * 60)
        report.append("RECOMMENDATION")
        report.append("-" * 60)
        report.append(result.recommendation)
        
        if result.review_reasons:
            report.append("")
            report.append("Review Reasons:")
            for reason in result.review_reasons:
                report.append(f"  • {reason}")
        
        report.append("=" * 60)
        
        return "\n".join(report)
