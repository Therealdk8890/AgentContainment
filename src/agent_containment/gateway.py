from .containment import ContainmentController
from .models import Action, Decision, DecisionType
from .policy import PolicyEngine

class ActionGateway:
    """The enforcement point between an agent and its tools."""

    def __init__(self, policy: PolicyEngine, containment: ContainmentController):
        self.policy = policy
        self.containment = containment
        self.history: list[Decision] = []

    def authorize(self, action: Action) -> Decision:
        if not self.containment.runtime.can_execute:
            decision = Decision(action.action_id, DecisionType.DENY, "agent runtime is not executable")
        else:
            decision = self.policy.evaluate(action)
        self.history.append(decision)
        if decision.decision is DecisionType.HALT:
            self.containment.halt()
        return decision

    def execute(self, action: Action, executor):
        decision = self.authorize(action)
        if decision.decision is not DecisionType.ALLOW:
            return decision
        return executor(action)
