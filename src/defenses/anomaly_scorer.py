"""Text anomaly scoring via character entropy and pattern analysis.

Detects anomalous payloads — leetspeak, Zalgo text, base64 gibberish, homoglyphs —
before they reach the model. Provides a pre-canonicalization defense layer.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass, field


@dataclass
class AnomalyScore:
    """Per-metric anomaly scores with overall verdict."""

    char_entropy: float = 0.0
    symbol_density: float = 0.0
    unicode_anomaly_ratio: float = 0.0
    repetition_score: float = 0.0
    trigram_perplexity: float = 0.0

    overall_anomaly: float = 0.0
    is_anomalous: bool = False
    flags: list[str] = field(default_factory=list)
    explanation: str = ""

    def to_dict(self) -> dict:
        return {
            "char_entropy": round(self.char_entropy, 4),
            "symbol_density": round(self.symbol_density, 4),
            "unicode_anomaly_ratio": round(self.unicode_anomaly_ratio, 4),
            "repetition_score": round(self.repetition_score, 4),
            "trigram_perplexity": round(self.trigram_perplexity, 4),
            "overall_anomaly": round(self.overall_anomaly, 4),
            "is_anomalous": self.is_anomalous,
            "flags": self.flags,
            "explanation": self.explanation,
        }


class TextAnomalyScorer:
    """Scores text for multiple anomaly dimensions.

    Useful as a pre-processing filter before canonicalization and defense pipeline.
    """

    _COMMON_TRIGRAMS: dict[str, float] = {
        "the": 0.035, "ing": 0.015, "and": 0.012, "ion": 0.010,
        "tio": 0.009, "ent": 0.009, "ati": 0.008, "for": 0.008,
        "her": 0.007, "tha": 0.007, "hat": 0.007, "ere": 0.007,
        "his": 0.007, "ver": 0.006, "all": 0.006, "ter": 0.006,
        "est": 0.006, "res": 0.006, "int": 0.006, "are": 0.006,
        "con": 0.006, "nce": 0.005, "men": 0.005, "pro": 0.005,
        "ons": 0.005, "ect": 0.005, "rea": 0.005, "one": 0.005,
        "com": 0.005, "ith": 0.005,
    }
    _COMMON_TRIGRAM_DEFAULT = 0.01

    def __init__(
        self,
        entropy_threshold: float = 4.2,
        symbol_density_threshold: float = 0.25,
        unicode_ratio_threshold: float = 0.15,
        repetition_threshold: float = 0.3,
        trigram_perplexity_threshold: float = 400.0,
        anomaly_threshold: float = 0.6,
    ) -> None:
        self.entropy_threshold = entropy_threshold
        self.symbol_density_threshold = symbol_density_threshold
        self.unicode_ratio_threshold = unicode_ratio_threshold
        self.repetition_threshold = repetition_threshold
        self.trigram_perplexity_threshold = trigram_perplexity_threshold
        self.anomaly_threshold = anomaly_threshold

    def score(self, text: str) -> AnomalyScore:
        if not text.strip():
            return AnomalyScore(explanation="Empty text.")

        entropy = self._char_entropy(text)
        sym_density = self._symbol_density(text)
        unicode_ratio = self._unicode_anomaly_ratio(text)
        rep_score = self._repetition_score(text)
        tri_perp = self._trigram_perplexity(text)

        e_score = max(0.0, (entropy - 3.8) / max(0.1, self.entropy_threshold - 3.8))
        s_score = sym_density / self.symbol_density_threshold
        u_score = unicode_ratio / self.unicode_ratio_threshold
        r_score = rep_score / self.repetition_threshold
        t_score = tri_perp / self.trigram_perplexity_threshold

        scores = [e_score, s_score, u_score, r_score, t_score]
        overall = max(scores)
        clamped = min(1.0, max(0.0, overall))
        is_anomalous = clamped >= self.anomaly_threshold

        flags = []
        if entropy > self.entropy_threshold:
            flags.append("high_char_entropy")
        if sym_density > self.symbol_density_threshold:
            flags.append("high_symbol_density")
        if unicode_ratio > self.unicode_ratio_threshold:
            flags.append("high_unicode_ratio")
        if rep_score > self.repetition_threshold:
            flags.append("high_repetition")
        if tri_perp > self.trigram_perplexity_threshold:
            flags.append("high_trigram_perplexity")

        explanation = "Text appears normal."
        if is_anomalous:
            explanation = f"Anomalous text detected: {', '.join(flags)}."

        return AnomalyScore(
            char_entropy=entropy,
            symbol_density=sym_density,
            unicode_anomaly_ratio=unicode_ratio,
            repetition_score=rep_score,
            trigram_perplexity=tri_perp,
            overall_anomaly=round(clamped, 4),
            is_anomalous=is_anomalous,
            flags=flags,
            explanation=explanation,
        )

    def _char_entropy(self, text: str) -> float:
        """Shannon entropy of character distribution. High for random/base64 text."""
        if not text:
            return 0.0
        counts = Counter(text.lower())
        total = len(text)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            entropy -= p * math.log2(p)
        return entropy

    def _symbol_density(self, text: str) -> float:
        """Ratio of non-alpha, non-space characters. High for leetspeak."""
        if not text:
            return 0.0
        symbols = sum(1 for c in text if not c.isalpha() and not c.isspace())
        return symbols / len(text)

    def _unicode_anomaly_ratio(self, text: str) -> float:
        """Ratio of non-ASCII characters. High for homoglyph/Zalgo attacks."""
        if not text:
            return 0.0
        non_ascii = sum(1 for c in text if ord(c) > 127)
        return non_ascii / len(text)

    def _repetition_score(self, text: str) -> float:
        """Detect repeated substrings indicating spam or DoS patterns."""
        if len(text) < 20:
            return 0.0
        lower = text.lower()
        window = 8
        seen: set[str] = set()
        repeat_count = 0
        for i in range(len(lower) - window + 1):
            chunk = lower[i:i + window]
            if chunk in seen:
                repeat_count += 1
            else:
                seen.add(chunk)
        return min(1.0, repeat_count / max(1, len(lower) // window))

    def _trigram_perplexity(self, text: str) -> float:
        """Approximate perplexity using common English trigram frequencies."""
        cleaned = re.sub(r"[^a-zA-Z ]", " ", text.lower())
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        if len(cleaned) < 30:
            return 20.0

        log_prob = 0.0
        count = 0
        for i in range(len(cleaned) - 2):
            trigram = cleaned[i:i + 3]
            prob = self._COMMON_TRIGRAMS.get(trigram, self._COMMON_TRIGRAM_DEFAULT)
            log_prob += math.log(prob)
            count += 1

        if count == 0:
            return 100.0

        avg_log = log_prob / count
        return math.exp(-avg_log)
