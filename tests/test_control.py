import pytest

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


def test_identity_token_is_revoked_by_containment_and_must_be_reissued_after_recovery():
    class FakeSupervisor:
        def create_agent(self, agent_id):
            return "/sys/fs/cgroup/demo"

        def attach_pid(self, path, pid):
            return None

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    service.register("agent-identity")
    service.create_workload("agent-identity")
    old_token = service.issue_identity_token("agent-identity", peer_pid=123)
    action = Action("agent-identity", "a1", "read", "workspace")
    membership = lambda pid, path: True

    assert service.authorize(
        action,
        identity_token=old_token,
        peer_pid=123,
        cgroup_membership=membership,
    ).decision is DecisionType.ALLOW

    service.contain("agent-identity")
    assert service.authorize(
        action,
        identity_token=old_token,
        peer_pid=123,
        cgroup_membership=membership,
    ).decision is DecisionType.DENY

    authorization = service.issue_recovery_authorization("agent-identity")
    service.recover("agent-identity", authorization)

    assert service.authorize(
        action,
        identity_token=old_token,
        peer_pid=123,
        cgroup_membership=membership,
    ).decision is DecisionType.DENY

    new_token = service.issue_identity_token("agent-identity", peer_pid=123)
    assert new_token != old_token
    assert service.authorize(
        action,
        identity_token=new_token,
        peer_pid=123,
        cgroup_membership=membership,
    ).decision is DecisionType.ALLOW


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


def test_recovery_authorization_is_single_use():
    service = ContainmentService()
    service.register("agent-recovery")
    service.contain("agent-recovery")
    authorization = service.issue_recovery_authorization("agent-recovery")
    service.recover("agent-recovery", authorization)

    with pytest.raises(PermissionError, match="recovery authorization is stale"):
        service.recover("agent-recovery", authorization)


def test_configure_containment_uses_public_api():
    service = ContainmentService()
    runtime = service.register("agent-public")
    controller = ContainmentController(
        runtime,
        CapabilitySet({"network", "filesystem.write"}),
    )

    service.configure_containment("agent-public", controller)
    report = service.contain("agent-public")

    assert report.complete
    assert controller.capabilities.capabilities == set()
    assert service.status("agent-public") is RuntimeState.CONTAINED


def test_configure_containment_rejects_different_runtime():
    service = ContainmentService()
    service.register("agent-public")
    foreign = ContainmentController(Runtime("other-agent"))

    try:
        service.configure_containment("agent-public", foreign)
    except ValueError as exc:
        assert "runtime" in str(exc)
    else:
        raise AssertionError("foreign containment runtime must be rejected")


def test_create_workload_is_controller_owned_and_unique():
    class FakeSupervisor:
        def create_agent(self, agent_id):
            return f"/sys/fs/cgroup/{agent_id}"

        def attach_pid(self, path, pid):
            return None

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    service.register("agent-workload")

    path = service.create_workload("agent-workload")
    assert path.endswith("/agent-workload")
    assert service.identity_cgroup("agent-workload") == path

    try:
        service.create_workload("agent-workload")
    except ValueError as exc:
        assert "already exists" in str(exc)
    else:
        raise AssertionError("duplicate workload creation must fail")


def test_authorization_is_fenced_against_concurrent_containment():
    import threading

    class FakeSupervisor:
        def create_agent(self, agent_id):
            return f"/sys/fs/cgroup/{agent_id}"

        def attach_pid(self, path, pid):
            return None

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    service.register("agent-race")
    service.create_workload("agent-race")
    token = service.issue_identity_token("agent-race", peer_pid=123)
    action = Action("agent-race", "race-1", "read", "workspace")

    membership_entered = threading.Event()
    release_membership = threading.Event()
    result = {}

    def membership(pid, path):
        membership_entered.set()
        assert release_membership.wait(timeout=2)
        return True

    def authorize():
        result["decision"] = service.authorize(
            action,
            identity_token=token,
            peer_pid=123,
            cgroup_membership=membership,
        )

    authorize_thread = threading.Thread(target=authorize)
    authorize_thread.start()
    assert membership_entered.wait(timeout=2)

    service.contain("agent-race")
    release_membership.set()
    authorize_thread.join(timeout=2)

    assert not authorize_thread.is_alive()
    assert result["decision"].decision is DecisionType.DENY
    assert result["decision"].reason == "agent identity is no longer authorized"


def test_runtime_snapshot_exposes_controller_owned_identity_and_epoch():
    service = ContainmentService()
    runtime = service.register("agent-snapshot")

    before = service.runtime_snapshot("agent-snapshot")
    assert before.runtime_id == runtime.runtime_id
    assert before.agent_id == "agent-snapshot"
    assert before.epoch == 0
    assert before.state is RuntimeState.ACTIVE

    service.contain("agent-snapshot")

    after = service.runtime_snapshot("agent-snapshot")
    assert after.runtime_id == runtime.runtime_id
    assert after.epoch == 1
    assert after.state is RuntimeState.CONTAINED
    assert not after.can_execute
