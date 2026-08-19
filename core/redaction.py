"""Central span-based redaction used by every detector."""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass

from .types import Detection


class RedactionError(ValueError):
    """Raised when a detector returns an unsafe or malformed span."""


@dataclass(frozen=True)
class _Span:
    start: int
    end: int
    labels: frozenset[str]


def _safe_label(value: object) -> str:
    label = re.sub(r"[^A-Za-z0-9_]+", "_", str(value)).strip("_").upper()
    return label or "VALUE"


def _validated_spans(text: str, detections: Iterable[Detection]) -> list[_Span]:
    spans: list[_Span] = []
    for detection in detections:
        if not detection.triggered:
            continue
        for item in detection.spans:
            start = item.get("start")
            end = item.get("end")
            if (
                isinstance(start, bool)
                or isinstance(end, bool)
                or not isinstance(start, int)
                or not isinstance(end, int)
                or start < 0
                or end <= start
                or end > len(text)
            ):
                raise RedactionError("detector returned an invalid redaction span")
            spans.append(
                _Span(
                    start=start,
                    end=end,
                    labels=frozenset({_safe_label(item.get("label", detection.detector))}),
                )
            )
    return spans


def redact(text: str, detections: Iterable[Detection]) -> str:
    """Redact all spans without allowing one detector to undo another.

    Overlapping spans are merged and their labels are preserved in a deterministic
    marker. No matched value is copied into the marker or an exception.
    """

    spans = sorted(_validated_spans(text, detections), key=lambda span: (span.start, span.end))
    if not spans:
        raise RedactionError("redaction requested without a valid sensitive span")

    merged: list[_Span] = []
    for span in spans:
        if not merged or span.start >= merged[-1].end:
            merged.append(span)
            continue
        previous = merged[-1]
        merged[-1] = _Span(
            start=previous.start,
            end=max(previous.end, span.end),
            labels=previous.labels | span.labels,
        )

    chunks: list[str] = []
    cursor = 0
    for span in merged:
        chunks.append(text[cursor : span.start])
        chunks.append(f"[REDACTED_{'+'.join(sorted(span.labels))}]")
        cursor = span.end
    chunks.append(text[cursor:])
    return "".join(chunks)
