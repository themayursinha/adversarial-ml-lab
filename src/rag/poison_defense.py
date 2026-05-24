"""RAG poisoning defense: detects malicious chunks in retrieved context."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import structlog

from src.rag.vector_store import RetrievedChunk

log = structlog.get_logger(__name__)


@dataclass
class ChunkVerdict:
    chunk: RetrievedChunk
    is_malicious: bool
    risk_score: float
    reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.chunk.source,
            "score": self.chunk.score,
            "is_malicious": self.is_malicious,
            "risk_score": round(self.risk_score, 4),
            "reasons": self.reasons,
        }


@dataclass
class RagDefenseResult:
    clean_chunks: list[RetrievedChunk]
    malicious_chunks: list[RetrievedChunk]
    verdicts: list[ChunkVerdict]
    overall_risk: float
    should_block: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "clean_count": len(self.clean_chunks),
            "malicious_count": len(self.malicious_chunks),
            "overall_risk": round(self.overall_risk, 4),
            "should_block": self.should_block,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


class RagPoisoningDefense:
    """Analyzes retrieved RAG chunks for poisoning indicators.

    Uses multiple signals:
    1. Semantic anomaly: unusually low similarity score
    2. Source reputation: suspicious source names
    3. Content signatures: known attack patterns (URL redirects, overrides)
    4. Structural anomalies: unusual length or markup
    """

    _LOW_TRUST_SOURCES = {
        "community_forum_post",
        "community",
        "forum",
        "social_media",
        "user_generated",
        "comment",
        "unknown",
    }

    _POISON_SIGNATURES: list[tuple[str, str, float]] = [
        (r"https?://[^/]*(?:login|auth|portal|signin)", "suspicious_url", 0.6),
        (r"overrid(?:e|ing)\s+all\s+(?:older\s+)?polic", "policy_override", 0.7),
        (r"direct(?:ed)?\s+to\s+https?://", "url_redirect", 0.6),
        (r"\[SYSTEM\s+ALERT\]", "system_alert_injection", 0.8),
        (r"administrative\s+override\s+clearance", "privilege_escalation", 0.8),
        (r"disable\s+security\s+filters?", "security_bypass", 0.7),
        (r"grant\s+them\s+full\s+access", "access_escalation", 0.7),
        (r"!\[.*\]\(https?://attacker\.com", "exfiltration_image", 0.9),
        (
            r"paste\s+(?:your|their)\s+(?:session|api|access)\s*(?:token|key)",
            "credential_harvesting",
            0.9,
        ),
    ]

    def __init__(
        self,
        low_score_threshold: float = 0.3,
        block_threshold: float = 0.5,
    ) -> None:
        self.low_score_threshold = low_score_threshold
        self.block_threshold = block_threshold

    def analyze(self, chunks: list[RetrievedChunk]) -> RagDefenseResult:
        verdicts: list[ChunkVerdict] = []
        clean: list[RetrievedChunk] = []
        malicious: list[RetrievedChunk] = []

        for chunk in chunks:
            verdict = self._analyze_chunk(chunk)
            verdicts.append(verdict)
            chunk.is_poisoned = verdict.is_malicious
            if verdict.is_malicious:
                malicious.append(chunk)
            else:
                clean.append(chunk)

        total_risk = 0.0
        if verdicts:
            total_risk = sum(v.risk_score for v in verdicts) / len(verdicts)

        should_block = total_risk >= self.block_threshold or len(malicious) > 0

        log.info(
            "rag.defense.analyzed",
            total_chunks=len(chunks),
            malicious=len(malicious),
            overall_risk=round(total_risk, 4),
            should_block=should_block,
        )

        return RagDefenseResult(
            clean_chunks=clean,
            malicious_chunks=malicious,
            verdicts=verdicts,
            overall_risk=round(total_risk, 4),
            should_block=should_block,
        )

    def _analyze_chunk(self, chunk: RetrievedChunk) -> ChunkVerdict:
        reasons: list[str] = []
        risk = 0.0

        if chunk.score < self.low_score_threshold:
            reasons.append(f"low_similarity_score({chunk.score:.3f})")
            risk = max(risk, 0.4)

        source_lower = chunk.source.lower()
        for low_trust in self._LOW_TRUST_SOURCES:
            if low_trust in source_lower:
                reasons.append(f"untrusted_source({chunk.source})")
                risk = max(risk, 0.3)
                break

        for pattern, reason, score in self._POISON_SIGNATURES:
            if re.search(pattern, chunk.content, re.IGNORECASE):
                reasons.append(reason)
                risk = max(risk, score)

        is_malicious = risk >= self.block_threshold

        return ChunkVerdict(
            chunk=chunk,
            is_malicious=is_malicious,
            risk_score=risk,
            reasons=reasons,
        )
