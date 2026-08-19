from __future__ import annotations

import pytest

from core.policy import Policy, PolicyBuilder, Rule
from core.types import Action, Detection, Stage


def _detection(name: str, confidence: float = 1.0, triggered: bool = True) -> Detection:
    return Detection(name, triggered, confidence)


def test_policy_uses_most_severe_matching_action() -> None:
    policy = (
        PolicyBuilder().on_input("pii", "redact", 0.5).on_input("jailbreak", "block", 0.5).build()
    )

    action, fired = policy.resolve(
        Stage.INPUT,
        [_detection("pii"), _detection("jailbreak")],
    )

    assert action is Action.BLOCK
    assert {rule.detector for rule in fired} == {"pii", "jailbreak"}


def test_policy_respects_threshold() -> None:
    policy = PolicyBuilder().on_input("pii", "redact", 0.8).build()

    action, fired = policy.resolve(Stage.INPUT, [_detection("pii", confidence=0.79)])

    assert action is Action.ALLOW
    assert fired == []


def test_policy_allows_non_triggered_detection() -> None:
    policy = PolicyBuilder().on_input("pii", "redact").build()

    action, fired = policy.resolve(Stage.INPUT, [_detection("pii", triggered=False)])

    assert action is Action.ALLOW
    assert fired == []


def test_policy_fails_closed_for_unmatched_trigger() -> None:
    policy = PolicyBuilder().build()

    action, fired = policy.resolve(Stage.INPUT, [_detection("new_detector")])

    assert action is Action.BLOCK
    assert fired[0].detector == "new_detector"


def test_policy_can_explicitly_allow_unmatched_trigger() -> None:
    policy = PolicyBuilder().on_unmatched("allow").build()

    action, fired = policy.resolve(Stage.INPUT, [_detection("advisory")])

    assert action is Action.ALLOW
    assert fired == []


def test_builder_returns_an_independent_rule_list() -> None:
    builder = PolicyBuilder().on_input("pii", "redact")
    first = builder.build()
    builder.on_input("jailbreak", "block")

    assert [rule.detector for rule in first.rules] == ["pii"]


@pytest.mark.parametrize("threshold", [-0.1, 1.1, float("inf"), float("nan")])
def test_rule_rejects_invalid_threshold(threshold: float) -> None:
    with pytest.raises(ValueError, match="threshold"):
        Rule(Stage.INPUT, "detector", Action.BLOCK, threshold)


def test_rule_rejects_empty_detector_name() -> None:
    with pytest.raises(ValueError, match="detector"):
        Rule(Stage.INPUT, "", Action.BLOCK)


def test_builder_rejects_unknown_action() -> None:
    with pytest.raises(ValueError):
        PolicyBuilder().on_input("pii", "quarantine")


def test_rule_rejects_non_enum_stage_and_action() -> None:
    with pytest.raises(TypeError, match="stage"):
        Rule("input", "pii", Action.BLOCK)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="action"):
        Rule(Stage.INPUT, "pii", "block")  # type: ignore[arg-type]


def test_policy_rejects_invalid_rule_collection() -> None:
    with pytest.raises(TypeError, match="rules"):
        Policy(rules=["not-a-rule"])  # type: ignore[list-item]


def test_detection_rejects_invalid_span_collection() -> None:
    with pytest.raises(TypeError, match="spans"):
        Detection("detector", True, 1.0, spans=["not-a-span"])  # type: ignore[list-item]


@pytest.mark.parametrize("confidence", [-0.1, 1.1, float("inf"), float("nan")])
def test_detection_rejects_invalid_confidence(confidence: float) -> None:
    with pytest.raises(ValueError, match="confidence"):
        Detection("detector", True, confidence)
