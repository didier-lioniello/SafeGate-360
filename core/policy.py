"""Declarative policy rules mapping detector outcomes to actions."""

from __future__ import annotations

import math
from dataclasses import dataclass, field

from .types import Action, Detection, Stage

_SEVERITY = {Action.ALLOW: 0, Action.WARN: 1, Action.REDACT: 2, Action.BLOCK: 3}


@dataclass(frozen=True)
class Rule:
    stage: Stage
    detector: str
    action: Action
    threshold: float = 0.5

    def __post_init__(self) -> None:
        if not isinstance(self.stage, Stage):
            raise TypeError("stage must be a Stage")
        if not isinstance(self.detector, str):
            raise TypeError("detector must be a string")
        if not self.detector.strip():
            raise ValueError("detector must be a non-empty name")
        if not isinstance(self.action, Action):
            raise TypeError("action must be an Action")
        if isinstance(self.threshold, bool) or not isinstance(self.threshold, (int, float)):
            raise TypeError("threshold must be numeric")
        if not math.isfinite(self.threshold) or not 0.0 <= self.threshold <= 1.0:
            raise ValueError("threshold must be between 0 and 1")

    def matches(self, detection: Detection, stage: Stage) -> bool:
        return (
            stage == self.stage
            and detection.detector == self.detector
            and detection.triggered
            and detection.confidence >= self.threshold
        )


@dataclass(frozen=True)
class Policy:
    rules: list[Rule] = field(default_factory=list)
    unmatched_action: Action = Action.BLOCK

    def __post_init__(self) -> None:
        if not isinstance(self.rules, list) or not all(
            isinstance(rule, Rule) for rule in self.rules
        ):
            raise TypeError("rules must be a list of Rule objects")
        if not isinstance(self.unmatched_action, Action):
            raise TypeError("unmatched_action must be an Action")

    def resolve(self, stage: Stage, detections: list[Detection]) -> tuple[Action, list[Rule]]:
        """Resolve the most severe action and the rules that produced it.

        Triggered detectors without a matching rule fail closed by default. This is
        important when a detector is added before its policy is updated.
        """

        fired: list[Rule] = []
        final = Action.ALLOW
        for detection in detections:
            configured = [
                rule
                for rule in self.rules
                if rule.stage == stage and rule.detector == detection.detector
            ]
            matching = [rule for rule in configured if rule.matches(detection, stage)]
            if detection.triggered and not configured and self.unmatched_action != Action.ALLOW:
                matching = [
                    Rule(
                        stage=stage,
                        detector=detection.detector,
                        action=self.unmatched_action,
                        threshold=0.0,
                    )
                ]
            fired.extend(matching)
            for rule in matching:
                if _SEVERITY[rule.action] > _SEVERITY[final]:
                    final = rule.action
        return final, fired


class PolicyBuilder:
    def __init__(self) -> None:
        self._rules: list[Rule] = []
        self._unmatched_action = Action.BLOCK

    def on_input(self, detector: str, action: str, threshold: float = 0.5) -> PolicyBuilder:
        self._rules.append(Rule(Stage.INPUT, detector, Action(action), threshold))
        return self

    def on_output(self, detector: str, action: str, threshold: float = 0.5) -> PolicyBuilder:
        self._rules.append(Rule(Stage.OUTPUT, detector, Action(action), threshold))
        return self

    def on_unmatched(self, action: str) -> PolicyBuilder:
        self._unmatched_action = Action(action)
        return self

    def build(self) -> Policy:
        return Policy(
            rules=list(self._rules),
            unmatched_action=self._unmatched_action,
        )
