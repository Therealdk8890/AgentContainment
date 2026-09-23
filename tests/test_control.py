from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.models import Action, DecisionType
from agent_containment.runtime import Runtime, RuntimeState


def test_controller_owns_containment_authority():
    service = ContainmentService()
    runtime = service.register("agent-1", metadata={"owner": "test"})
    assert service.status("agent-1") is RuntimeState.ACTIVE
    assert runtime.can_execute
    report = service.contain("agent-1")
    assert report.complete
    assert service.status("agent-1") is RuntimeState.CONTAINED
    assert not runtime.can_execute


def test_controller_can_manage_preconfigured_enforcement():
    service = ContainmentService()
    runtime = Runtime("agent-2")
    controller = ContainmentController(runtime, CapabilitySet({"network"}))
    service.register("agent-2", containment=controller)
    report = service.contain("agent-2")
    assert report.complete
    assert controller.capabilities.capabilities == set()


def test_duplicate_registration_is_rejected():
    service = ContainmentService()
    service.register("agent-1")
    try:
        service.register("agent-1")
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate registration must fail")


def test_identity_token_denies_missing_and_wrong_credentials():
    service = ContainmentService()
    service.register("agent-1")
    action = Action("agent-1", "a1", "read", "workspace")
    assert service.authorize(action).decision is DecisionType.DENY
    assert service.authorize(action, identity_token="wrong").decision is DecisionType.DENY


def test_cgroup_identity_requires_membership():
    class FakeSupervisor:
        def create_agent(self, agent_id):
            return "/sys/fs/cgroup/demo"
        def attach_pid(self, path, pid):
            return None

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    service.register("agent-1")
    service.create_workload("agent-1")
    token = service.issue_identity_token("agent-1")

    action = Action("agent-1", "a1", "read", "workspace")
    assert service.authorize(
        action,
        identity_token=token,
        peer_pid=123,
        cgroup_membership=lambda pid, path: False,
    ).decision is DecisionType.DENY

    assert service.authorize(
        action,
        identity_token=token,
        peer_pid=123,
        cgroup_membership=lambda pid, path: True,
    ).decision is DecisionType.ALLOW


def test_cgroup_identity_cannot_be_bypassed_by_matching_pid_alone():
    class FakeSupervisor:
        def create_agent(self, agent_id):
            return "/sys/fs/cgroup/demo"
        def attach_pid(self, path, pid):
            return None

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    service.register("agent-1")
    service.create_workload("agent-1")
    token = service.issue_identity_token("agent-1", peer_pid=123)

    action = Action("agent-1", "a1", "read", "workspace")
    assert service.authorize(
        action,
        identity_token=token,
        peer_pid=123,
        cgroup_membership=lambda pid, path: False,
    ).decision is DecisionType.DENY
