"""Core types shared by detectors, policies, redaction, and the gate."""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

_SAFE_METADATA = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")


def _safe_metadata_value(value: object) -> str:
    sanitized = re.sub(r"[^A-Za-z0-9_.:-]+", "_", str(value)).strip("_.:-")
    return (sanitized or "unknown")[:80]


class Stage(StrEnum):
    INPUT = "input"
    OUTPUT = "output"


class Action(StrEnum):
    ALLOW = "allow"
    WARN = "warn"
    REDACT = "redact"
    BLOCK = "block"


@dataclass(frozen=True)
class Detection:
    """One detector's verdict for a single value.

    Detectors may describe sensitive locations through spans, but must never put the
    matched value in ``reason``. A span uses ``start``, ``end``, and ``label`` keys.
    """

    detector: str
    triggered: bool
    confidence: float
    reason: str = ""
    spans: list[dict[str, Any]] = field(default_factory=list)
    error_code: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.detector, str):
            raise TypeError("detector must be a string")
        if not _SAFE_METADATA.fullmatch(self.detector):
            raise ValueError("detector must be a safe category name of at most 80 characters")
        if not isinstance(self.triggered, bool):
            raise TypeError("triggered must be a boolean")
        if isinstance(self.confidence, bool) or not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be numeric")
        if not math.isfinite(float(self.confidence)) or not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not isinstance(self.spans, list) or not all(
            isinstance(span, dict) for span in self.spans
        ):
            raise TypeError("spans must be a list of dictionaries")
        if self.error_code is not None:
            if not isinstance(self.error_code, str):
                raise TypeError("error_code must be a string or None")
            if not _SAFE_METADATA.fullmatch(self.error_code):
                raise ValueError("error_code must be a safe category name")


@dataclass(frozen=True)
class GuardResult:
    """A guard decision.

    Raw input is deliberately not retained on the result. ``output_text`` is either
    safe-to-return content or ``None`` for blocked decisions.
    """

    request_id: str
    allowed: bool
    action: Action
    stage: Stage
    output_text: str | None = None
    detections: list[Detection] = field(default_factory=list)
    reason: str = ""
    latency_ms: float = 0.0

    def to_audit_record(
        self,
        *,
        timestamp: str,
        audit_session_id: str,
        input_fingerprint: str | None,
        output_fingerprint: str | None,
    ) -> dict[str, Any]:
        """Return metadata safe for an audit log.

        Detector reasons and raw values are intentionally excluded because custom
        detectors may accidentally echo the content they inspect.
        """

        return {
            "schema_version": 1,
            "timestamp": timestamp,
            "audit_session_id": audit_session_id,
            "request_id": self.request_id,
            "allowed": self.allowed,
            "action": self.action.value,
            "stage": self.stage.value,
            "reason": self.reason,
            "latency_ms": round(self.latency_ms, 3),
            "input_fingerprint": input_fingerprint,
            "output_fingerprint": output_fingerprint,
            "detections": [
                {
                    "detector": detection.detector,
                    "triggered": detection.triggered,
                    "confidence": round(detection.confidence, 4),
                    "span_count": len(detection.spans),
                    "span_labels": sorted(
                        {
                            _safe_metadata_value(span.get("label", "unknown"))
                            for span in detection.spans
                        }
                    ),
                    "error_code": detection.error_code,
                }
                for detection in self.detections
            ],
        }
