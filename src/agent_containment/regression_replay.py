"""Replay helpers for deterministic regression fixtures.

Replay executes only the local policy decision model. It never invokes an
enforcer, recovery path, external provider, or runtime control API.
"""
from __future__ import annotations

from dataclasses import dataclass

from .models import Action, DecisionType
from .policy import PolicyEngine
from .regression import RegressionFixture


@dataclass(frozen=True)
class RegressionReplayResult:
    policy_decision: str
    containment_required: bool


def replay_fixture(fixture: RegressionFixture) -> RegressionReplayResult:
    policy = fixture.context.get("policy")
    if not isinstance(policy, dict):
        raise ValueError("fixture context must contain a policy mapping")

    denied = policy.get("denied_operations", [])
    max_risk = policy.get("max_risk", 80)
    if not isinstance(denied, list) or not all(isinstance(x, str) for x in denied):
        raise ValueError("policy.denied_operations must be a list of strings")
    if not isinstance(max_risk, int):
        raise ValueError("policy.max_risk must be an integer")

    engine = PolicyEngine(denied_operations=set(denied), max_risk=max_risk)
    operations = fixture.action_sequence
    if not operations:
        raise ValueError("fixture action_sequence cannot be empty")

    for index, operation in enumerate(operations):
        decision = engine.evaluate(
            Action(
                agent_id=fixture.agent_id,
                action_id=f"{fixture.incident_id}:{index}",
                operation=operation,
                resource=str(fixture.context.get("resource", "regression")),
                risk=int(fixture.context.get("risk", 0)) if index == len(operations) - 1 else 0,
            )
        )

    containment_required = decision.decision in {
        DecisionType.HALT,
        DecisionType.DENY,
        DecisionType.CONTAIN,
    }
    return RegressionReplayResult(
        policy_decision=decision.decision.value,
        containment_required=containment_required,
    )


def assert_fixture_replays(fixture: RegressionFixture) -> None:
    result = replay_fixture(fixture)
    if result.policy_decision != fixture.policy_decision.lower():
        raise AssertionError(
            f"replay policy mismatch: expected {fixture.policy_decision!r}, "
            f"got {result.policy_decision!r}"
        )
    expected_containment = fixture.containment_result not in {
        "not_required", "not-configured", "none"
    }
    if result.containment_required != expected_containment:
        raise AssertionError(
            "replay containment mismatch: "
            f"expected {expected_containment!r}, got {result.containment_required!r}"
        )
