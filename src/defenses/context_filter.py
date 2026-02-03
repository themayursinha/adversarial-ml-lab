"""
Context-Aware Output Filter
===========================
Defense mechanism against indirect prompt injection attacks.

This filter analyzes LLM outputs to detect when the model may have
been influenced by hidden instructions in input documents. It uses
multiple detection strategies to identify suspicious outputs.

SECURITY: This is a defense-in-depth component. Always validate
outputs through multiple channels.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
import re
from enum import Enum


class RiskLevel(Enum):
    """Risk level for detected issues."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class FilterResult:
    """Result of output filtering."""
    original_output: str
    filtered_output: str
    was_modified: bool
    risk_level: RiskLevel
    detections: list[dict]
    explanation: str
    confidence: float  # 0.0 to 1.0


class ContextAwareFilter:
    """
    Context-aware output filter to detect and mitigate prompt injection.
    
    This defense works by:
    1. Checking if output matches expected task type
    2. Detecting injection signatures in output
    3. Measuring semantic deviation from expected behavior
    4. Applying content-based filtering rules
    """
    
    # Patterns that indicate successful injection
    INJECTION_INDICATORS = [
        (r"hacked|compromised|pwned|breached", "Injection success indicator"),
        (r"data\s*exfiltrat", "Data exfiltration mention"),
        (r"ignore(d)?\s+(all\s+)?instructions?", "Instruction override mention"),
        (r"bypass(ed|ing)?\s+(security|safety|filter)", "Bypass mention"),
        (r"admin\s*mode|god\s*mode|debug\s*mode", "Privilege escalation mention"),
        (r"system\s*prompt|reveal\s*(the)?\s*prompt", "System prompt exposure"),
        (r"jailbreak|jailbroken", "Jailbreak mention"),
        (r"attacker\.com|evil\.com|hacker", "Malicious domain/entity"),
    ]
    
    # Patterns for expected task outputs
    TASK_PATTERNS = {
        "summarize": [
            r"summary|summarize|key\s*points?|highlights?|overview",
            r"the\s+document|the\s+text|the\s+content",
        ],
        "classify": [
            r"classification|category|class|label",
            r"confidence|probability|score",
        ],
        "chat": [
            r"I('d|\s+would)\s+be\s+happy\s+to|I\s+can|let\s+me|here's",
        ],
    }
    
    def __init__(
        self,
        sensitivity: float = 0.5,
        block_on_detection: bool = True,
    ) -> None:
        """
        Initialize the filter.
        
        Args:
            sensitivity: Detection sensitivity (0.0 to 1.0)
            block_on_detection: Whether to block/modify suspicious outputs
        """
        self.sensitivity = sensitivity
        self.block_on_detection = block_on_detection
        
        # Compile patterns for efficiency
        self._compiled_indicators = [
            (re.compile(pattern, re.IGNORECASE), desc)
            for pattern, desc in self.INJECTION_INDICATORS
        ]
    
    def detect_injection_indicators(self, text: str) -> list[dict]:
        """
        Detect injection indicators in text.
        
        Args:
            text: Text to analyze
            
        Returns:
            List of detection results
        """
        detections = []
        
        for pattern, description in self._compiled_indicators:
            matches = pattern.findall(text)
            if matches:
                detections.append({
                    "type": "injection_indicator",
                    "description": description,
                    "matches": matches[:5],  # Limit matches shown
                    "severity": "high",
                })
        
        return detections
    
    def check_task_alignment(
        self,
        output: str,
        expected_task: str,
    ) -> tuple[bool, float, str]:
        """
        Check if output aligns with expected task type.
        
        Args:
            output: LLM output to check
            expected_task: Expected task type (summarize, classify, chat)
            
        Returns:
            Tuple of (is_aligned, confidence, explanation)
        """
        patterns = self.TASK_PATTERNS.get(expected_task, [])
        if not patterns:
            return True, 0.5, "Unknown task type, cannot verify alignment"
        
        matches = 0
        for pattern in patterns:
            if re.search(pattern, output, re.IGNORECASE):
                matches += 1
        
        alignment_score = matches / len(patterns)
        is_aligned = alignment_score >= 0.3  # At least 30% pattern match
        
        if is_aligned:
            explanation = f"Output appears aligned with '{expected_task}' task"
        else:
            explanation = f"Output may not match expected '{expected_task}' task"
        
        return is_aligned, alignment_score, explanation
    
    def calculate_risk_level(
        self,
        detections: list[dict],
        task_aligned: bool,
    ) -> RiskLevel:
        """Calculate overall risk level based on detections."""
        high_severity_count = sum(
            1 for d in detections if d.get("severity") == "high"
        )
        
        if high_severity_count >= 2 or (high_severity_count >= 1 and not task_aligned):
            return RiskLevel.CRITICAL
        elif high_severity_count >= 1:
            return RiskLevel.HIGH
        elif len(detections) >= 2:
            return RiskLevel.MEDIUM
        elif len(detections) >= 1:
            return RiskLevel.LOW
        else:
            return RiskLevel.LOW
    
    def filter_output(
        self,
        output: str,
        input_context: Optional[str] = None,
        expected_task: str = "general",
    ) -> FilterResult:
        """
        Filter LLM output for potential injection effects.
        
        Args:
            output: The LLM output to filter
            input_context: Original input context (for comparison)
            expected_task: What task the output should be performing
            
        Returns:
            FilterResult with analysis and potentially modified output
        """
        detections = []
        
        # 1. Check for injection indicators
        injection_detections = self.detect_injection_indicators(output)
        detections.extend(injection_detections)
        
        # 2. Check task alignment
        is_aligned, alignment_score, alignment_explanation = self.check_task_alignment(
            output, expected_task
        )
        if not is_aligned:
            detections.append({
                "type": "task_misalignment",
                "description": alignment_explanation,
                "confidence": alignment_score,
                "severity": "medium",
            })
        
        # 3. Check for suspicious length changes
        if input_context:
            input_words = len(input_context.split())
            output_words = len(output.split())
            # Very short output for long input might indicate injection
            if input_words > 100 and output_words < 20:
                detections.append({
                    "type": "suspicious_length",
                    "description": "Output suspiciously short compared to input",
                    "severity": "low",
                })
        
        # Calculate risk level
        risk_level = self.calculate_risk_level(detections, is_aligned)
        
        # Determine if we should modify the output
        was_modified = False
        filtered_output = output
        
        if self.block_on_detection and risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]:
            was_modified = True
            filtered_output = self._create_safe_response(risk_level, detections, expected_task)
        
        # Calculate confidence
        confidence = 1.0 - (len(detections) * 0.15)
        confidence = max(0.1, min(1.0, confidence))
        
        # Build explanation
        if detections:
            explanation = f"Detected {len(detections)} issue(s). Risk level: {risk_level.value}."
            if was_modified:
                explanation += " Output was modified for safety."
        else:
            explanation = "No issues detected. Output appears safe."
        
        return FilterResult(
            original_output=output,
            filtered_output=filtered_output,
            was_modified=was_modified,
            risk_level=risk_level,
            detections=detections,
            explanation=explanation,
            confidence=confidence,
        )
    
    def _create_safe_response(
        self,
        risk_level: RiskLevel,
        detections: list[dict],
        expected_task: str,
    ) -> str:
        """Create a safe response when blocking suspicious output."""
        detection_types = [d["type"] for d in detections]
        
        response = (
            f"⚠️ **Security Alert: Potential Injection Detected**\n\n"
            f"The system has blocked this output due to potential prompt injection.\n\n"
            f"**Risk Level**: {risk_level.value.upper()}\n"
            f"**Issues Detected**: {', '.join(detection_types)}\n\n"
            f"The original request to '{expected_task}' could not be completed safely.\n"
            f"Please review the input document for hidden instructions or malicious content."
        )
        
        return response
    
    def get_filter_stats(self) -> dict:
        """Get statistics about the filter configuration."""
        return {
            "sensitivity": self.sensitivity,
            "block_on_detection": self.block_on_detection,
            "num_injection_patterns": len(self.INJECTION_INDICATORS),
            "supported_tasks": list(self.TASK_PATTERNS.keys()),
        }
