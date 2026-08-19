from __future__ import annotations

import pytest

from core.redaction import RedactionError, redact
from core.types import Detection


def _detection(detector: str, start: int, end: int, label: str) -> Detection:
    return Detection(
        detector=detector,
        triggered=True,
        confidence=1.0,
        spans=[{"start": start, "end": end, "label": label}],
    )


def test_redaction_composes_non_overlapping_detectors() -> None:
    text = "alpha private beta hidden gamma"
    first = _detection("first", 6, 13, "email")
    second = _detection("second", 19, 25, "token")

    result = redact(text, [first, second])

    assert result == "alpha [REDACTED_EMAIL] beta [REDACTED_TOKEN] gamma"
    assert "private" not in result
    assert "hidden" not in result


def test_redaction_merges_overlapping_spans() -> None:
    text = "0123456789"
    first = _detection("first", 2, 7, "pii")
    second = _detection("second", 5, 9, "secret")

    assert redact(text, [first, second]) == "01[REDACTED_PII+SECRET]9"


def test_redaction_keeps_adjacent_spans_separate() -> None:
    text = "abcdefgh"
    first = _detection("first", 0, 4, "one")
    second = _detection("second", 4, 8, "two")

    assert redact(text, [first, second]) == "[REDACTED_ONE][REDACTED_TWO]"


def test_redaction_sanitizes_labels() -> None:
    text = "secret"
    detection = _detection("custom", 0, len(text), "custom value!")

    assert redact(text, [detection]) == "[REDACTED_CUSTOM_VALUE]"


@pytest.mark.parametrize(
    "start,end",
    [(-1, 2), (2, 2), (3, 2), (0, 99), (True, 2)],
)
def test_redaction_rejects_invalid_spans(start, end) -> None:
    detection = _detection("invalid", start, end, "value")

    with pytest.raises(RedactionError, match="invalid redaction span"):
        redact("value", [detection])


def test_redaction_rejects_missing_spans() -> None:
    detection = Detection("empty", True, 1.0)

    with pytest.raises(RedactionError, match="without a valid sensitive span"):
        redact("value", [detection])


def test_redaction_ignores_non_triggered_spans() -> None:
    detection = Detection(
        detector="inactive",
        triggered=False,
        confidence=0.0,
        spans=[{"start": 0, "end": 5, "label": "value"}],
    )

    with pytest.raises(RedactionError):
        redact("value", [detection])
