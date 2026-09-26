from __future__ import annotations

from agent_containment.control import ContainmentService
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.containment import ContainmentController
from agent_containment.models import DecisionType
from agent_containment.runtime import RuntimeState


class VerifiedEnforcer:
    name = "race-test-provider"

    def contain(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "contained")

    def verify_contained(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "verified")

    def release(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "released")

    def verify_released(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "verified")


def test_stale_recovery_authorization_cannot_cross_new_containment_epoch():
    service = ContainmentService()
    runtime = service.register("agent-1")
    service.configure_containment(
        "agent-1", ContainmentController(runtime, enforcers=[VerifiedEnforcer()])
    )

    first = service.contain("agent-1")
    authorization = service.issue_recovery_authorization("agent-1")

    service.recover("agent-1", authorization)
    assert runtime.state is RuntimeState.ACTIVE
    assert runtime.epoch == first.epoch + 1

    second = service.contain("agent-1")
    assert second.epoch == first.epoch + 2

    try:
        service.recover("agent-1", authorization)
    except PermissionError:
        pass
    else:
        raise AssertionError("stale recovery authorization crossed a new containment epoch")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == second.epoch


def test_containment_serializes_against_recovery_authorization_and_release():
    events = []
    service = ContainmentService(event_sink=events.append)
    runtime = service.register("agent-1")
    service.configure_containment(
        "agent-1", ContainmentController(runtime, enforcers=[VerifiedEnforcer()])
    )

    report = service.contain("agent-1")
    authorization = service.issue_recovery_authorization("agent-1")

    service.recover("agent-1", authorization)
    service.contain("agent-1")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch > report.epoch
    assert any(e.event_type == "recovery_completed" for e in events)
    assert any(e.event_type == "containment_certified" for e in events)
