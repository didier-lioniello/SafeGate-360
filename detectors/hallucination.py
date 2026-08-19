"""
Hallucination detector.

Stub: no grounding context available in the default signature. In real deployments,
override this with a detector that takes (input, output, retrieved_context) and runs
an NLI check: for each sentence in `output`, does `context` entail it?

This reference provides only a weak heuristic for unhedged claims with specific numbers.
It must not be interpreted as factuality or grounding verification.
"""

from __future__ import annotations

import re

from core.types import Detection

CLAIM_MARKERS = [
    r"\b\d{4}\b",  # years
    r"\$\s?\d+(\.\d+)?\s?(m|bn|billion|million|k)?",  # monetary
    r"\b\d+(\.\d+)?%\b",  # percentages
    r"\baccording to\b",
    r"\bresearch shows\b",
    r"\bstudies (find|show|prove)\b",
]


def detect_hallucination(_input_text: str, output_text: str) -> Detection:
    risky = 0
    for pat in CLAIM_MARKERS:
        risky += len(re.findall(pat, output_text, flags=re.IGNORECASE))

    # Heuristic: lots of specific claims and no hedging language -> higher risk.
    hedged = bool(
        re.search(
            r"\b(may|might|could|possibly|roughly|about|approximately)\b",
            output_text,
            flags=re.IGNORECASE,
        )
    )

    triggered = risky >= 2 and not hedged
    conf = min(0.3 + 0.1 * risky, 0.8) if triggered else 0.0

    return Detection(
        detector="hallucination",
        triggered=triggered,
        confidence=conf,
        reason=(
            f"{risky} unhedged factual claims" if triggered else f"{risky} claims, hedged={hedged}"
        ),
    )
