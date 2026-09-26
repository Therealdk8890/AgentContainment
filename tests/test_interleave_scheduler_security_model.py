from __future__ import annotations

import pytest

it = pytest.importorskip("interleave_test")

from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.runtime import RuntimeState


class VerifiedEnforcer:
    name = "interleave-test-provider"

    def contain(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "contained")

    def verify_contained(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "verified")

    def release(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "released")

    def verify_released(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "verified")


@it.interleave(iterations=100, seed=0, strategy="dfs", max_preemptions=1)
def test_containment_recovery_public_operations_are_serialized():
    """Explore the ordering of the two controller-owned critical operations.

    AgentContainment's service lock intentionally makes contain() and recover()
    linearizable public operations. We therefore treat each public call as an
    atomic region and exhaustively explore the ordering between them.

    If recovery wins, it must complete before the newer containment operation.
    If containment wins, the older recovery authorization must be rejected.
    In neither ordering may the final runtime be executable.
    """
    service = ContainmentService()
    runtime = service.register("agent-1")
    service.configure_containment(
        "agent-1",
        ContainmentController(runtime, enforcers=[VerifiedEnforcer()]),
    )

    with it.no_interleave():
        service.contain("agent-1")
        authorization = service.issue_recovery_authorization("agent-1")

    outcomes: list[str] = []

    def recover():
        with it.no_interleave():
            try:
                service.recover("agent-1", authorization)
            except PermissionError:
                outcomes.append("stale")
            else:
                outcomes.append("recovered")

    def contain():
        with it.no_interleave():
            service.contain("agent-1")
            outcomes.append("contained")

    first = it.spawn(recover, name="recover")
    second = it.spawn(contain, name="contain")
    first.join()
    second.join()

    assert runtime.state is RuntimeState.CONTAINED
    assert sorted(outcomes) in (["contained", "recovered"], ["contained", "stale"])
    if "stale" in outcomes:
        assert runtime.epoch == 2
    else:
        assert runtime.epoch == 3
