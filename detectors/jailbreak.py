"""Pattern checks for a narrow set of common English jailbreak phrases.

The checks are easy to paraphrase or obfuscate and make no coverage claim. Additional
classifiers also require adversarial evaluation and do not turn this signal into a
security guarantee.
"""

from __future__ import annotations

import re

from core.types import Detection

JAILBREAK_PATTERNS = [
    (
        r"ignore (?:(?:all|any|previous|prior)\s+){0,2}(instructions|rules|prompts)",
        0.9,
        "ignore_instructions",
    ),
    (r"you are now (dan|a ?dan|in developer mode|jailbroken)", 0.95, "persona_override"),
    (r"pretend (you are|to be) (an unrestricted|a jailbroken)", 0.85, "persona_override"),
    (
        r"disregard (the |your )?(system|prior) (prompt|message|instructions)",
        0.9,
        "disregard_system",
    ),
    (
        r"from now on[^.]{0,60}(no restrictions|without limits|uncensored)",
        0.85,
        "unrestricted_mode",
    ),
    (r"\b(dan|do anything now)\b[^.]{0,40}mode", 0.8, "dan_mode"),
    (
        r"role[- ]?play.{0,40}(without|no) (restrictions|limits|rules)",
        0.75,
        "roleplay_unrestricted",
    ),
]


def detect_jailbreak(text: str) -> Detection:
    lower = text.lower()
    matches = []
    max_conf = 0.0

    for pat, conf, label in JAILBREAK_PATTERNS:
        if re.search(pat, lower):
            matches.append(label)
            max_conf = max(max_conf, conf)

    triggered = bool(matches)
    return Detection(
        detector="jailbreak",
        triggered=triggered,
        confidence=max_conf,
        reason=f"matched patterns: {matches}" if triggered else "no jailbreak patterns",
    )
