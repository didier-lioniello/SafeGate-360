"""Small deterministic lexical signal for a testable reference implementation.

This deliberately avoids loading a model or making a network call. It is not a
toxicity classifier and should be replaced or supplemented for a real deployment.
"""

from __future__ import annotations

import re

from core.types import Detection

_SIGNALS: dict[str, re.Pattern[str]] = {
    "threat": re.compile(r"\b(?:kill|murder|attack|hurt)\b", re.IGNORECASE),
    "hate": re.compile(r"\b(?:racist|slur)\b", re.IGNORECASE),
    "violence": re.compile(r"\bviolence\b", re.IGNORECASE),
}


def _score(text: str) -> tuple[float, list[str]]:
    categories = sorted(name for name, pattern in _SIGNALS.items() if pattern.search(text))
    if not categories:
        return 0.0, []
    return min(0.65 + 0.1 * (len(categories) - 1), 0.9), categories


def detect_toxicity_input(text: str) -> Detection:
    confidence, categories = _score(text)
    return Detection(
        detector="toxicity",
        triggered=confidence >= 0.6,
        confidence=confidence,
        reason=f"lexical categories={categories}" if categories else "no lexical signal",
    )


def detect_toxicity_output(_input_text: str, output_text: str) -> Detection:
    confidence, categories = _score(output_text)
    return Detection(
        detector="toxicity",
        triggered=confidence >= 0.6,
        confidence=confidence,
        reason=f"lexical categories={categories}" if categories else "no lexical signal",
    )
