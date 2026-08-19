"""High-precision detector for common credential shapes.

Patterns are intentionally limited and can miss provider-specific or transformed
credentials. Values are represented only as spans and are never copied to reasons.
"""

from __future__ import annotations

import re

from core.types import Detection

SECRET_PATTERNS: dict[str, re.Pattern[str]] = {
    "anthropic_key": re.compile(r"sk-ant-[A-Za-z0-9_-]{20,}"),
    "openai_key": re.compile(r"sk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}"),
    "aws_access": re.compile(r"(?:AKIA|ASIA)[0-9A-Z]{16}"),
    "aws_secret": re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*[A-Za-z0-9/+=]{40}"),
    "github_pat": re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})"),
    "google_api": re.compile(r"AIza[0-9A-Za-z_-]{35}"),
    "private_key": re.compile(r"-----BEGIN (?:(?:RSA|EC|DSA|OPENSSH) )?PRIVATE KEY-----"),
    "jwt": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
}


def _detect_secret_shapes(text: str, *, detector: str) -> Detection:
    spans: list[dict[str, int | str]] = []
    hit_types: set[str] = set()
    for name, pattern in SECRET_PATTERNS.items():
        for match in pattern.finditer(text):
            hit_types.add(name)
            spans.append({"start": match.start(), "end": match.end(), "label": name})

    triggered = bool(spans)
    return Detection(
        detector=detector,
        triggered=triggered,
        confidence=1.0 if triggered else 0.0,
        reason=(
            f"credential-shaped value detected, types={sorted(hit_types)}"
            if triggered
            else "no credential-shaped values"
        ),
        spans=spans,
    )


def detect_secret_input(text: str) -> Detection:
    return _detect_secret_shapes(text, detector="secret")


def detect_secret_leak(_input_text: str, output_text: str) -> Detection:
    return _detect_secret_shapes(output_text, detector="secret_leak")
