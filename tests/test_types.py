from __future__ import annotations

import pytest

from core import Detection


@pytest.mark.parametrize(
    ("field", "kwargs"),
    [
        ("detector", {"detector": "raw customer text"}),
        ("error code", {"error_code": "private failure detail"}),
    ],
)
def test_audit_metadata_categories_reject_free_text(field: str, kwargs: dict) -> None:
    values = {
        "detector": "pii",
        "triggered": True,
        "confidence": 1.0,
        "spans": [],
        "error_code": None,
    }
    values.update(kwargs)

    with pytest.raises(ValueError, match="safe category"):
        Detection(**values)


def test_safe_audit_metadata_categories_are_accepted() -> None:
    detection = Detection(
        detector="credential.cloud-key",
        triggered=True,
        confidence=0.95,
        spans=[{"start": 0, "end": 1, "label": "CLOUD_KEY"}],
        error_code="match:synthetic",
    )

    assert detection.detector == "credential.cloud-key"


def test_audit_span_labels_are_sanitized_before_writing() -> None:
    detection = Detection(
        detector="pii",
        triggered=True,
        confidence=1.0,
        spans=[{"start": 0, "end": 1, "label": "raw customer text!"}],
    )

    from core import Action, GuardResult, Stage

    record = GuardResult(
        request_id="request",
        allowed=False,
        action=Action.BLOCK,
        stage=Stage.INPUT,
        detections=[detection],
    ).to_audit_record(
        timestamp="2026-01-01T00:00:00+00:00",
        audit_session_id="session",
        input_fingerprint=None,
        output_fingerprint=None,
    )

    assert record["detections"][0]["span_labels"] == ["raw_customer_text"]
