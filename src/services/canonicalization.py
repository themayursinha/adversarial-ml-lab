"""Input canonicalization utilities used by defense pipelines."""

from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass

_ZERO_WIDTH_PATTERN = re.compile(r"[\u200b\u200c\u200d\ufeff\u2060\u00ad]")
_CONTROL_PATTERN = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


@dataclass
class CanonicalizationResult:
    """Represents canonicalization output and transformations applied."""

    original_text: str
    canonical_text: str
    removed_zero_width_count: int
    replaced_control_count: int


def canonicalize_text(text: str) -> CanonicalizationResult:
    """Normalize text while preserving semantics for downstream security checks."""
    normalized = unicodedata.normalize("NFKC", text)

    zero_width_matches = _ZERO_WIDTH_PATTERN.findall(normalized)
    without_zero_width = _ZERO_WIDTH_PATTERN.sub("", normalized)

    control_matches = _CONTROL_PATTERN.findall(without_zero_width)
    canonical = _CONTROL_PATTERN.sub(" ", without_zero_width)

    return CanonicalizationResult(
        original_text=text,
        canonical_text=canonical,
        removed_zero_width_count=len(zero_width_matches),
        replaced_control_count=len(control_matches),
    )
