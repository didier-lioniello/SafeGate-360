from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from core import Action, AuditWriteError, Detection, Policy, PolicyBuilder, SafeGate, Stage
from examples.fixtures import build_fixture, synthetic_cloud_key
from policies import default_policy


def _audit_records(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines()]


def _default_gate(tmp_path: Path, **kwargs) -> SafeGate:
    return SafeGate(
        policy=default_policy(),
        log_path=tmp_path / "audit.jsonl",
        **kwargs,
    )


def test_clean_input_is_allowed_and_audited(tmp_path: Path) -> None:
    gate = _default_gate(tmp_path)

    result = gate.check_input(build_fixture("clean"))

    assert result.allowed is True
    assert result.action is Action.ALLOW
    assert result.stage is Stage.INPUT
    assert result.output_text == build_fixture("clean")
    records = _audit_records(tmp_path / "audit.jsonl")
    assert len(records) == 1
    assert records[0]["schema_version"] == 1
    assert records[0]["allowed"] is True


def test_input_pii_is_redacted_without_retaining_raw_text(tmp_path: Path) -> None:
    text = build_fixture("synthetic_email")

    result = _default_gate(tmp_path).check_input(text)

    assert result.allowed is True
    assert result.action is Action.REDACT
    assert result.output_text is not None
    assert "[REDACTED_EMAIL]" in result.output_text
    assert text not in (tmp_path / "audit.jsonl").read_text()
    assert "demo.user" not in (tmp_path / "audit.jsonl").read_text()


def test_multiple_redactions_do_not_restore_prior_values(tmp_path: Path) -> None:
    text = "first-sensitive and second-sensitive"

    def first_detector(value: str) -> Detection:
        start = value.index("first-sensitive")
        return Detection(
            "first",
            True,
            1.0,
            spans=[{"start": start, "end": start + len("first-sensitive"), "label": "one"}],
        )

    def second_detector(value: str) -> Detection:
        start = value.index("second-sensitive")
        return Detection(
            "second",
            True,
            1.0,
            spans=[{"start": start, "end": start + len("second-sensitive"), "label": "two"}],
        )

    policy = PolicyBuilder().on_input("first", "redact").on_input("second", "redact").build()
    gate = SafeGate(
        policy,
        input_detectors=[first_detector, second_detector],
        output_detectors=[],
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.check_input(text)

    assert result.output_text == "[REDACTED_ONE] and [REDACTED_TWO]"


def test_blocked_input_never_calls_model(tmp_path: Path) -> None:
    called = False

    def model(_prompt: str) -> str:
        nonlocal called
        called = True
        return "not reached"

    result = _default_gate(tmp_path, llm_fn=model).guard(build_fixture("jailbreak"))

    assert result.action is Action.BLOCK
    assert result.stage is Stage.INPUT
    assert called is False


def test_credential_shaped_input_is_blocked_before_model(tmp_path: Path) -> None:
    called = False

    def model(_prompt: str) -> str:
        nonlocal called
        called = True
        return "not reached"

    result = _default_gate(tmp_path, llm_fn=model).guard(build_fixture("synthetic_cloud_key"))

    assert result.action is Action.BLOCK
    assert result.stage is Stage.INPUT
    assert result.output_text is None
    assert called is False
    assert synthetic_cloud_key() not in (tmp_path / "audit.jsonl").read_text()


def test_model_receives_redacted_input_instead_of_raw_pii(tmp_path: Path) -> None:
    raw_prompt = build_fixture("synthetic_email")
    received: list[str] = []

    def model(prompt: str) -> str:
        received.append(prompt)
        return "Safe deterministic response."

    result = _default_gate(tmp_path, llm_fn=model).guard(raw_prompt)

    assert result.allowed is True
    assert received == ["Please reply to the synthetic address [REDACTED_EMAIL]."]
    assert "demo.user" not in received[0]


def test_output_detectors_receive_redacted_input_instead_of_raw_pii(tmp_path: Path) -> None:
    raw_prompt = build_fixture("synthetic_email")
    inspected_inputs: list[str] = []

    def inspect_input(input_text: str, _output_text: str) -> Detection:
        inspected_inputs.append(input_text)
        return Detection("pii", False, 0.0, reason="no output PII")

    gate = SafeGate(
        default_policy(),
        output_detectors=[inspect_input],
        llm_fn=lambda _prompt: "Safe deterministic response.",
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.guard(raw_prompt)

    assert result.allowed is True
    assert inspected_inputs == ["Please reply to the synthetic address [REDACTED_EMAIL]."]
    assert "demo.user" not in inspected_inputs[0]


def test_output_pii_is_redacted_with_correlated_audit_records(tmp_path: Path) -> None:
    response = build_fixture("synthetic_email")
    gate = _default_gate(tmp_path, llm_fn=lambda _prompt: response)

    result = gate.guard(build_fixture("clean"))

    assert result.action is Action.REDACT
    assert result.stage is Stage.OUTPUT
    assert result.output_text is not None
    assert "[REDACTED_EMAIL]" in result.output_text
    records = _audit_records(tmp_path / "audit.jsonl")
    assert [record["stage"] for record in records] == ["input", "output"]
    assert len({record["request_id"] for record in records}) == 1
    assert "demo.user" not in (tmp_path / "audit.jsonl").read_text()


def test_credential_shaped_output_is_blocked(tmp_path: Path) -> None:
    response = f"Generated value: {synthetic_cloud_key()}"
    gate = _default_gate(tmp_path, llm_fn=lambda _prompt: response)

    result = gate.guard(build_fixture("clean"))

    assert result.allowed is False
    assert result.action is Action.BLOCK
    assert result.output_text is None
    assert synthetic_cloud_key() not in (tmp_path / "audit.jsonl").read_text()


def test_warn_action_allows_output_unchanged(tmp_path: Path) -> None:
    response = "Research shows growth was 42% in 2025."
    gate = _default_gate(tmp_path, llm_fn=lambda _prompt: response)

    result = gate.guard(build_fixture("clean"))

    assert result.allowed is True
    assert result.action is Action.WARN
    assert result.output_text == response


def test_input_detector_exception_fails_closed_without_error_details(tmp_path: Path) -> None:
    private_error_detail = "do-not-log-this-detail"

    def broken(_text: str) -> Detection:
        raise RuntimeError(private_error_detail)

    gate = SafeGate(
        default_policy(),
        input_detectors=[broken],
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.check_input("safe text")

    assert result.action is Action.BLOCK
    assert result.reason.startswith("input_detector_error")
    assert private_error_detail not in (tmp_path / "audit.jsonl").read_text()


def test_anonymous_detector_failure_still_fails_closed_and_audits(tmp_path: Path) -> None:
    def raise_private_error(_text: str) -> Detection:
        raise RuntimeError("private failure")

    raise_private_error.__name__ = "<anonymous detector>"
    gate = SafeGate(
        default_policy(),
        input_detectors=[raise_private_error],
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.check_input("safe text")

    assert result.action is Action.BLOCK
    assert result.reason == "input_detector_error:anonymous_detector"
    assert _audit_records(tmp_path / "audit.jsonl")[0]["allowed"] is False


def test_output_detector_exception_fails_closed(tmp_path: Path) -> None:
    def broken(_input: str, _output: str) -> Detection:
        raise RuntimeError("private failure")

    gate = SafeGate(
        default_policy(),
        input_detectors=[],
        output_detectors=[broken],
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.check_output("input", "output")

    assert result.action is Action.BLOCK
    assert result.reason.startswith("output_detector_error")


def test_non_detection_return_fails_closed(tmp_path: Path) -> None:
    def invalid(_text: str):
        return {"triggered": False}

    gate = SafeGate(
        default_policy(),
        input_detectors=[invalid],
        log_path=tmp_path / "audit.jsonl",
    )

    assert gate.check_input("safe").action is Action.BLOCK


def test_invalid_redaction_span_fails_closed(tmp_path: Path) -> None:
    def invalid_span(_text: str) -> Detection:
        return Detection(
            "pii",
            True,
            1.0,
            spans=[{"start": 0, "end": 999, "label": "pii"}],
        )

    gate = SafeGate(
        default_policy(),
        input_detectors=[invalid_span],
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.check_input("short")

    assert result.action is Action.BLOCK
    assert result.reason == "input_policy_or_redaction_error"


def test_unexpected_policy_error_fails_closed(tmp_path: Path) -> None:
    class BrokenPolicy(Policy):
        def resolve(self, stage, detections):
            raise RuntimeError("private policy failure")

    gate = SafeGate(
        BrokenPolicy(),
        input_detectors=[],
        log_path=tmp_path / "audit.jsonl",
    )

    result = gate.check_input("safe")

    assert result.action is Action.BLOCK
    assert result.reason == "input_policy_or_redaction_error"
    assert "private policy failure" not in (tmp_path / "audit.jsonl").read_text()


def test_invalid_input_type_fails_closed_and_is_audited(tmp_path: Path) -> None:
    result = _default_gate(tmp_path).check_input(42)  # type: ignore[arg-type]

    assert result.action is Action.BLOCK
    assert result.reason == "invalid_input_type"
    assert _audit_records(tmp_path / "audit.jsonl")[0]["input_fingerprint"] is None


def test_input_size_limit_fails_closed(tmp_path: Path) -> None:
    gate = SafeGate(default_policy(), log_path=tmp_path / "audit.jsonl", max_text_chars=4)

    result = gate.check_input("12345")

    assert result.action is Action.BLOCK
    assert result.reason == "input_too_large"


def test_output_size_limit_fails_closed(tmp_path: Path) -> None:
    gate = SafeGate(
        default_policy(),
        input_detectors=[],
        output_detectors=[],
        log_path=tmp_path / "audit.jsonl",
        max_text_chars=4,
    )

    result = gate.check_output("1234", "12345")

    assert result.action is Action.BLOCK
    assert result.reason == "output_too_large"


def test_guard_without_model_callable_fails_closed(tmp_path: Path) -> None:
    result = _default_gate(tmp_path).guard(build_fixture("clean"))

    assert result.action is Action.BLOCK
    assert result.stage is Stage.OUTPUT
    assert result.reason == "llm_not_configured"


def test_model_exception_fails_closed_without_exception_text(tmp_path: Path) -> None:
    detail = "private model error"

    def model(_prompt: str) -> str:
        raise RuntimeError(detail)

    result = _default_gate(tmp_path, llm_fn=model).guard(build_fixture("clean"))

    assert result.reason == "llm_execution_error"
    assert detail not in (tmp_path / "audit.jsonl").read_text()


def test_non_string_model_output_fails_closed(tmp_path: Path) -> None:
    gate = _default_gate(tmp_path, llm_fn=lambda _prompt: None)  # type: ignore[arg-type]

    result = gate.guard(build_fixture("clean"))

    assert result.action is Action.BLOCK
    assert result.reason == "invalid_llm_output_type"


def test_audit_omits_custom_detector_reason_and_raw_text(tmp_path: Path) -> None:
    raw = "sensitive custom value"

    def reflective(text: str) -> Detection:
        return Detection("reflective", False, 0.0, reason=text)

    gate = SafeGate(
        default_policy(),
        input_detectors=[reflective],
        log_path=tmp_path / "audit.jsonl",
        audit_hmac_key=b"a" * 32,
    )

    gate.check_input(raw)
    audit_text = (tmp_path / "audit.jsonl").read_text()

    assert raw not in audit_text
    assert "reflective" in audit_text


def test_audit_fingerprint_is_stable_within_gate(tmp_path: Path) -> None:
    gate = _default_gate(tmp_path, audit_hmac_key=b"b" * 32)
    text = build_fixture("clean")

    gate.check_input(text)
    gate.check_input(text)

    records = _audit_records(tmp_path / "audit.jsonl")
    assert records[0]["input_fingerprint"] == records[1]["input_fingerprint"]
    assert records[0]["request_id"] != records[1]["request_id"]


def test_audit_file_permissions_are_private(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "audit.jsonl"
    SafeGate(default_policy(), log_path=path).check_input(build_fixture("clean"))

    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_audit_destination_directory_raises(tmp_path: Path) -> None:
    gate = SafeGate(default_policy(), log_path=tmp_path)

    with pytest.raises(AuditWriteError, match="could not be written"):
        gate.check_input(build_fixture("clean"))


def test_unencodable_input_causes_sanitized_audit_failure(tmp_path: Path) -> None:
    gate = SafeGate(
        default_policy(),
        input_detectors=[],
        log_path=tmp_path / "audit.jsonl",
    )

    with pytest.raises(AuditWriteError, match="could not be written"):
        gate.check_input("\ud800")


@pytest.mark.skipif(not hasattr(os, "O_NOFOLLOW"), reason="platform has no O_NOFOLLOW")
def test_audit_symlink_is_rejected(tmp_path: Path) -> None:
    destination = tmp_path / "destination.jsonl"
    destination.touch()
    link = tmp_path / "audit.jsonl"
    link.symlink_to(destination)
    gate = SafeGate(default_policy(), log_path=link)

    with pytest.raises(AuditWriteError):
        gate.check_input(build_fixture("clean"))


@pytest.mark.parametrize("key", [b"short", "not-bytes", 123])
def test_constructor_rejects_weak_or_invalid_audit_key(key) -> None:
    with pytest.raises(ValueError, match="audit_hmac_key"):
        SafeGate(default_policy(), audit_hmac_key=key)  # type: ignore[arg-type]


@pytest.mark.parametrize("limit", [0, -1])
def test_constructor_rejects_non_positive_limit(limit: int) -> None:
    with pytest.raises(ValueError, match="positive"):
        SafeGate(default_policy(), max_text_chars=limit)
