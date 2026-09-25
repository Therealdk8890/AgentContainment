import pytest

from agent_containment.control import ContainmentService
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.containment import ContainmentController
from agent_containment.runtime import Runtime


def test_recovery_authorization_cannot_cross_agents():
    service = ContainmentService()
    service.register("agent-a")
    service.register("agent-b")
    service.contain("agent-a")
    auth = service.issue_recovery_authorization("agent-a")

    with pytest.raises(PermissionError, match="bound to another agent"):
        service.recover("agent-b", auth)


def test_old_recovery_authorization_is_invalid_after_new_containment_epoch():
    service = ContainmentService()
    service.register("agent-epoch")
    service.contain("agent-epoch")
    old_auth = service.issue_recovery_authorization("agent-epoch")
    service.recover("agent-epoch", old_auth)
    service.contain("agent-epoch")

    with pytest.raises(PermissionError, match="stale"):
        service.recover("agent-epoch", old_auth)


def test_recovery_requires_durable_incident():
    service = ContainmentService()
    service.register("agent-active")

    with pytest.raises(RuntimeError, match="no durably recoverable containment incident"):
        service.issue_recovery_authorization("agent-active")


def test_recovery_capability_is_rotated_after_successful_recovery():
    service = ContainmentService()
    runtime = service.register("agent-rotate")
    service.contain("agent-rotate")
    auth = service.issue_recovery_authorization("agent-rotate")
    old_capability = auth._capability

    service.recover("agent-rotate", auth)

    assert runtime.can_execute
    assert service._agents["agent-rotate"].recovery_capability is not old_capability


class FailingReleaseController(ContainmentController):
    def release_enforcers(self):
        return ["cilium: release failed"]


def test_release_failure_keeps_runtime_contained():
    service = ContainmentService()
    runtime = Runtime("agent-release")
    service.register("agent-release", containment=FailingReleaseController(runtime))
    service.contain("agent-release")
    auth = service.issue_recovery_authorization("agent-release")

    with pytest.raises(RuntimeError, match="could not be released"):
        service.recover("agent-release", auth)

    assert not runtime.can_execute


def test_failed_recovery_does_not_consume_authorization_when_release_fails():
    service = ContainmentService()
    runtime = Runtime("agent-release-retry")
    service.register("agent-release-retry", containment=FailingReleaseController(runtime))
    service.contain("agent-release-retry")
    auth = service.issue_recovery_authorization("agent-release-retry")

    with pytest.raises(RuntimeError):
        service.recover("agent-release-retry", auth)

    with pytest.raises(RuntimeError):
        service.recover("agent-release-retry", auth)

    assert not runtime.can_execute
