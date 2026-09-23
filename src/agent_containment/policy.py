from .models import Action, Decision, DecisionType

class PolicyEngine:
    def __init__(self, denied_operations: set[str] | None = None, max_risk: int = 80):
        self.denied_operations = denied_operations or set()
        self.max_risk = max_risk

    def evaluate(self, action: Action) -> Decision:
        if action.operation in self.denied_operations:
            return Decision(action.action_id, DecisionType.HALT, f"operation '{action.operation}' is denied by policy")
        if action.risk >= self.max_risk:
            return Decision(action.action_id, DecisionType.HALT, f"risk {action.risk} exceeds threshold {self.max_risk}")
        return Decision(action.action_id, DecisionType.ALLOW, "within policy")
