"""Deterministic per-action and stateful sequence policy enforcement."""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass

from .models import Action, Decision, DecisionType


@dataclass(frozen=True)
class SequenceRule:
    """A forbidden ordered sequence of operation names."""

    name: str
    sequence: tuple[str, ...]
    decision: DecisionType = DecisionType.HALT

    def __post_init__(self) -> None:
        if not self.name or not self.sequence:
            raise ValueError("sequence rules require a name and non-empty sequence")
        if any(not isinstance(item, str) or not item for item in self.sequence):
            raise ValueError("sequence entries must be non-empty strings")


class PolicyEngine:
    """Deterministic policy engine with controller-owned action history."""

    def __init__(
        self,
        denied_operations: set[str] | None = None,
        max_risk: int = 80,
        sequence_rules: list[SequenceRule] | None = None,
        history_limit: int = 256,
    ):
        if not 0 <= max_risk <= 100:
            raise ValueError("max_risk must be from 0 to 100")
        if history_limit < 1:
            raise ValueError("history_limit must be positive")
        self.denied_operations = set(denied_operations or set())
        self.max_risk = max_risk
        self.sequence_rules = tuple(sequence_rules or ())
        self.history: deque[str] = deque(maxlen=history_limit)

    def evaluate(self, action: Action) -> Decision:
        """Evaluate one action against static rules and prior controller history.

        The action is evaluated against sequence rules before it is appended to
        history. Only actions that pass policy are committed to history.
        """
        if action.operation in self.denied_operations:
            return Decision(action.action_id, DecisionType.HALT,
                            f"operation '{action.operation}' is denied by policy")
        if action.risk >= self.max_risk:
            return Decision(action.action_id, DecisionType.HALT,
                            f"risk {action.risk} exceeds threshold {self.max_risk}")

        candidate = tuple(self.history) + (action.operation,)
        for rule in self.sequence_rules:
            if len(candidate) >= len(rule.sequence) and candidate[-len(rule.sequence):] == rule.sequence:
                return Decision(
                    action.action_id,
                    rule.decision,
                    f"sequence rule '{rule.name}' matched",
                )

        self.history.append(action.operation)
        return Decision(action.action_id, DecisionType.ALLOW, "within policy")

    def reset_history(self) -> None:
        """Clear controller-owned policy history."""
        self.history.clear()
