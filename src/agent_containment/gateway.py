from .containment import ContainmentController
from .egress import EgressController, EgressLease
from .models import Action, Decision, DecisionType
from .policy import PolicyEngine
from .runtime import ExecutionLease


class ActionGateway:
    """The enforcement point between an agent and its tools."""

    def __init__(self, policy: PolicyEngine, containment: ContainmentController):
        self.policy = policy
        self.containment = containment
        self.egress = EgressController(containment.runtime)
        self.containment.attach_egress(self.egress)
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

    def acquire_lease(self) -> ExecutionLease | None:
        return self.containment.runtime.acquire_lease()

    def execute_with_lease(self, action: Action, lease: ExecutionLease, executor):
        if not self.containment.runtime.lease_valid(lease):
            decision = Decision(action.action_id, DecisionType.DENY,
                                "execution lease invalidated by runtime state change")
            self.history.append(decision)
            return decision

        decision = self.authorize(action)
        if decision.decision is not DecisionType.ALLOW:
            return decision

        if not self.containment.runtime.lease_valid(lease):
            decision = Decision(action.action_id, DecisionType.DENY,
                                "execution lease invalidated before side effect")
            self.history.append(decision)
            return decision

        return executor(action)

    def acquire_egress_lease(self) -> EgressLease | None:
        return self.egress.acquire_lease()

    def execute_egress(self, action: Action, lease: EgressLease, executor):
        if not self.egress.authorize(lease):
            return Decision(action.action_id, DecisionType.DENY,
                            "egress lease invalidated by runtime state change")

        decision = self.authorize(action)
        if decision.decision is not DecisionType.ALLOW:
            return decision

        if not self.egress.authorize(lease):
            return Decision(action.action_id, DecisionType.DENY,
                            "egress lease invalidated before network side effect")

        return executor(action)

    def execute(self, action: Action, executor):
        decision = self.authorize(action)
        if decision.decision is not DecisionType.ALLOW:
            return decision
        return executor(action)
