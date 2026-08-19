"""Deterministic, high-precision PII pattern detector.

The detector intentionally covers only a small set of structured identifiers. It is
not a replacement for locale-aware entity recognition or a privacy review.
"""

from __future__ import annotations

import re
from collections.abc import Callable

from core.types import Detection

EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b")
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE_CANDIDATE = re.compile(r"(?<!\w)\+?\d[\d().\s-]{5,}\d(?!\w)")
IPV4 = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")
CARD_CANDIDATE = re.compile(r"(?<!\d)(?:\d[ -]?){12,18}\d(?!\d)")


def _valid_ipv4(value: str) -> bool:
    return all(0 <= int(part) <= 255 for part in value.split("."))


def _valid_luhn(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19 or len(set(digits)) == 1:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _valid_phone(value: str) -> bool:
    digits = [char for char in value if char.isdigit()]
    separators = [char for char in value if not char.isdigit() and char != "+"]
    return 7 <= len(digits) <= 15 and len(separators) >= 2


def _collect(
    text: str,
    *,
    label: str,
    pattern: re.Pattern[str],
    validator: Callable[[str], bool] | None = None,
) -> list[dict[str, int | str]]:
    spans: list[dict[str, int | str]] = []
    for match in pattern.finditer(text):
        if validator is not None and not validator(match.group(0)):
            continue
        spans.append({"start": match.start(), "end": match.end(), "label": label})
    return spans


def detect_pii(text: str, label: str = "pii") -> Detection:
    spans: list[dict[str, int | str]] = []
    spans.extend(_collect(text, label="email", pattern=EMAIL))
    spans.extend(_collect(text, label="ssn", pattern=SSN))
    spans.extend(_collect(text, label="phone", pattern=PHONE_CANDIDATE, validator=_valid_phone))
    spans.extend(_collect(text, label="ipv4", pattern=IPV4, validator=_valid_ipv4))
    spans.extend(_collect(text, label="credit_card", pattern=CARD_CANDIDATE, validator=_valid_luhn))

    distinct_types = {str(span["label"]) for span in spans}
    triggered = bool(spans)
    confidence = min(1.0, 0.5 + 0.15 * len(distinct_types)) if triggered else 0.0
    return Detection(
        detector=label,
        triggered=triggered,
        confidence=confidence,
        reason=(
            f"{len(spans)} structured PII span(s), types={sorted(distinct_types)}"
            if triggered
            else "no structured PII"
        ),
        spans=spans,
    )
