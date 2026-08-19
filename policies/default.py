"""Conservative demonstration policy.

This is an auditable example, not a production policy. Tune it against a threat
model, representative evaluation set, and documented false-positive budget.
"""

from core.policy import PolicyBuilder


def default_policy():
    return (
        PolicyBuilder()
        .on_input("pii", action="redact", threshold=0.4)
        .on_input("secret", action="block", threshold=0.5)
        .on_input("jailbreak", action="block", threshold=0.7)
        .on_input("prompt_injection", action="block", threshold=0.6)
        .on_input("toxicity", action="block", threshold=0.6)
        .on_output("pii_leak", action="redact", threshold=0.4)
        .on_output("secret_leak", action="block", threshold=0.5)
        .on_output("toxicity", action="block", threshold=0.6)
        .on_output("hallucination", action="warn", threshold=0.5)
        .on_unmatched("block")
        .build()
    )
