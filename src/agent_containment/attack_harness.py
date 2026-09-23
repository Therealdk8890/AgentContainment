"""Controlled adversarial harness for testing containment invariants.

This module never executes real external commands, network calls, or destructive
operations. It models an agent attempting to bypass the control plane.
"""
from dataclasses import dataclass, field
from .models import Action, DecisionType
from .gateway import ActionGateway
from .containment import ContainmentController

@dataclass
class AttackAttempt:
    name: str
    action: Action

@dataclass
class AttackResult:
    name: str
    decision: DecisionType
    blocked: bool
    reason: str

@dataclass
class AttackHarness:
    gateway: ActionGateway
    containment: ContainmentController
    results: list[AttackResult] = field(default_factory=list)

    def attempt(self, attack: AttackAttempt) -> AttackResult:
        decision = self.gateway.authorize(attack.action)
        result = AttackResult(
            name=attack.name,
            decision=decision.decision,
            blocked=decision.decision is not DecisionType.ALLOW,
            reason=decision.reason,
        )
        self.results.append(result)
        return result

    def assert_contained(self) -> None:
        failures = [r for r in self.results if not r.blocked]
        if failures:
            names = ", ".join(r.name for r in failures)
            raise AssertionError(f"containment bypasses detected: {names}")
