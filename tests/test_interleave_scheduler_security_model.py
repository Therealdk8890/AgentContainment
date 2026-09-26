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


@it.interleave(iterations=500, seed=0, strategy="dfs", max_preemptions=2)
def test_containment_recovery_interleavings_remain_fail_closed():
    service = ContainmentService()
    runtime = service.register("agent-1")
    service.configure_containment(
        "agent-1",
        ContainmentController(runtime, enforcers=[VerifiedEnforcer()]),
    )

    service.contain("agent-1")
    authorization = service.issue_recovery_authorization("agent-1")
    recovery_succeeded = []

    def recover():
        try:
            service.recover("agent-1", authorization)
            recovery_succeeded.append(True)
        except PermissionError:
            recovery_succeeded.append(False)

    def contain():
        service.contain("agent-1")

    first = it.spawn(recover, name="recover")
    second = it.spawn(contain, name="contain")
    first.join()
    second.join()

    assert runtime.state is RuntimeState.CONTAINED
    assert recovery_succeeded in ([True], [False])
    assert runtime.epoch in (2, 3)
