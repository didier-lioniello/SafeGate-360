from __future__ import annotations

from detectors.hallucination import detect_hallucination
from detectors.injection import detect_prompt_injection
from detectors.jailbreak import detect_jailbreak
from detectors.pii import detect_pii
from detectors.secrets import detect_secret_input, detect_secret_leak
from detectors.toxicity import detect_toxicity_input, detect_toxicity_output
from examples.fixtures import build_fixture, synthetic_cloud_key, synthetic_jwt


def _labels(detection) -> set[str]:
    return {str(span["label"]) for span in detection.spans}


def test_pii_detects_runtime_synthetic_email_and_identifier() -> None:
    text = f"{build_fixture('synthetic_email')} {build_fixture('synthetic_ssn')}"

    detection = detect_pii(text)

    assert detection.triggered is True
    assert {"email", "ssn"} <= _labels(detection)
    assert "@" not in detection.reason
    assert "123" not in detection.reason


def test_pii_detects_luhn_valid_card_built_from_fragments() -> None:
    card = " ".join(("4111", "1111", "1111", "1111"))

    detection = detect_pii(f"Synthetic test card: {card}")

    assert "credit_card" in _labels(detection)


def test_pii_rejects_non_luhn_long_number() -> None:
    number = " ".join(("1234", "5678", "9012", "3456"))

    detection = detect_pii(f"Order reference: {number}")

    assert "credit_card" not in _labels(detection)


def test_pii_validates_ipv4_octets() -> None:
    valid = ".".join(("192", "0", "2", "10"))
    invalid = ".".join(("999", "0", "2", "10"))

    assert "ipv4" in _labels(detect_pii(valid))
    assert "ipv4" not in _labels(detect_pii(invalid))


def test_pii_detects_structured_phone() -> None:
    phone = " ".join(("+33", "1", "23", "45", "67", "89"))

    assert "phone" in _labels(detect_pii(phone))


def test_pii_clean_text_is_not_triggered() -> None:
    detection = detect_pii("Summarize the public changelog.")

    assert detection.triggered is False
    assert detection.confidence == 0.0
    assert detection.spans == []


def test_secret_detector_finds_runtime_cloud_key() -> None:
    value = synthetic_cloud_key()

    detection = detect_secret_leak("prompt", f"Generated value: {value}")

    assert detection.triggered is True
    assert "aws_access" in _labels(detection)
    assert value not in detection.reason


def test_input_secret_detector_uses_input_policy_name() -> None:
    detection = detect_secret_input(synthetic_cloud_key())

    assert detection.triggered is True
    assert detection.detector == "secret"


def test_secret_detector_finds_runtime_token_shape() -> None:
    value = synthetic_jwt()

    detection = detect_secret_leak("prompt", value)

    assert detection.triggered is True
    assert "jwt" in _labels(detection)
    assert value not in detection.reason


def test_secret_detector_finds_runtime_private_key_marker() -> None:
    marker = "".join(("-----BEGIN ", "PRIVATE ", "KEY-----"))

    detection = detect_secret_leak("prompt", marker)

    assert detection.triggered is True
    assert "private_key" in _labels(detection)


def test_secret_detector_ignores_documentation_placeholder() -> None:
    detection = detect_secret_leak("prompt", "Set PROVIDER_KEY through your secret manager.")

    assert detection.triggered is False
    assert detection.spans == []


def test_jailbreak_detector_matches_known_instruction_override() -> None:
    detection = detect_jailbreak(build_fixture("jailbreak"))

    assert detection.triggered is True
    assert detection.confidence >= 0.9


def test_jailbreak_detector_allows_benign_request() -> None:
    assert detect_jailbreak(build_fixture("clean")).triggered is False


def test_prompt_injection_detector_matches_delimiter_fixture() -> None:
    detection = detect_prompt_injection(build_fixture("prompt_injection"))

    assert detection.triggered is True
    assert detection.confidence >= 0.7


def test_prompt_injection_detector_allows_normal_heading() -> None:
    assert detect_prompt_injection("### Summary: public changes").triggered is False


def test_toxicity_signal_is_deterministic_for_input_and_output() -> None:
    text = build_fixture("toxicity_signal")

    input_detection = detect_toxicity_input(text)
    output_detection = detect_toxicity_output("prompt", text)

    assert input_detection.triggered is True
    assert output_detection.triggered is True
    assert input_detection.confidence == output_detection.confidence


def test_toxicity_clean_text_is_not_triggered() -> None:
    assert detect_toxicity_input(build_fixture("clean")).triggered is False


def test_hallucination_heuristic_warns_on_unhedged_claim_markers() -> None:
    output = "Research shows growth was 42% in 2025."

    detection = detect_hallucination("prompt", output)

    assert detection.triggered is True
    assert detection.confidence >= 0.5


def test_hallucination_heuristic_respects_hedging_marker() -> None:
    output = "Research shows growth may have been 42% in 2025."

    assert detect_hallucination("prompt", output).triggered is False
