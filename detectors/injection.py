"""
Prompt injection detector.

Indirect injection in untrusted data is difficult to distinguish from legitimate text.
These heuristics screen only a few explicit instruction markers. They are a testable
signal, not a complete prompt-injection defense.
"""

from __future__ import annotations

import re

from core.types import Detection

INJECTION_MARKERS = [
    (r"### (system|instruction|prompt)[\s:]", 0.8),
    (r"<\|(system|endoftext|im_start)\|>", 0.9),
    (r"\[\[?(system|instruction)\]?\]", 0.7),
    (r"new instructions?:\s", 0.75),
    (r"forget (everything|all) (above|prior|previous)", 0.9),
    (r"your (real|true) (task|goal|instructions?) (is|are)", 0.7),
    (r"output the following verbatim", 0.6),
]


def detect_prompt_injection(text: str) -> Detection:
    lower = text.lower()
    hits = []
    max_conf = 0.0

    for pat, conf in INJECTION_MARKERS:
        if re.search(pat, lower):
            hits.append(pat)
            max_conf = max(max_conf, conf)

    triggered = bool(hits)
    return Detection(
        detector="prompt_injection",
        triggered=triggered,
        confidence=max_conf,
        reason=f"{len(hits)} injection marker(s) detected" if triggered else "no markers",
    )
