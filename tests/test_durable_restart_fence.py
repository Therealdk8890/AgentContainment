import pytest

from agent_containment.control import ContainmentService
from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.incident_state import IncidentRegistry, IncidentState
from agent_containment.runtime import Runtime, RuntimeState
from agent_containment.runtime_fence import RuntimeFenceRegistry


class FailingIncidentRegistry(IncidentRegistry):
    def record_containment(self, *args, **kwargs):
        raise OSError("incident store unavailable")


def test_restart_stays_contained_when_incident_persistence_fails(tmp_path):
    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"

    first = ContainmentService(
        incidents=FailingIncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    first.register("agent-persistence-failure")

    report = first.contain("agent-persistence-failure")

    assert first.status("agent-persistence-failure") is RuntimeState.CONTAINED
    assert not report.durable
    assert "incident persistence unavailable" in report.persistence_failures[0]

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=__import__("agent_containment.runtime_fence", fromlist=["RuntimeFenceRegistry"]).RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-persistence-failure")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert runtime.acquire_lease() is None


def test_durable_fence_blocks_restart_even_without_incident_record(tmp_path):
    fence_path = tmp_path / "fences.json"

    first_fences = RuntimeFenceRegistry(fence_path)
    first_fences.prepare("agent-fence-only", 1)

    restarted = ContainmentService(
        incidents=IncidentRegistry(tmp_path / "incidents.json"),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-fence-only")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    incident = restarted.incident("agent-fence-only")
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert "reconstructed from durable containment fence" in (incident.reason or "")
    assert runtime.acquire_lease() is None


def test_recovery_does_not_clear_fence_if_fence_persistence_fails(tmp_path):
    class FailingClearFenceRegistry(RuntimeFenceRegistry):
        def clear(self, agent_id):
            raise OSError("fence store unavailable")

    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"

    fences = RuntimeFenceRegistry(fence_path)
    service = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=fences,
    )
    service.register("agent-fence-recovery")
    service.contain("agent-fence-recovery")

    recovering = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=FailingClearFenceRegistry(fence_path),
    )
    recovering.register("agent-fence-recovery")
    authorization = recovering.issue_recovery_authorization("agent-fence-recovery")

    with pytest.raises(RuntimeError, match="durable recovery fence could not be cleared"):
        recovering.recover("agent-fence-recovery", authorization)

    assert recovering.status("agent-fence-recovery") is RuntimeState.CONTAINED
    incident = recovering.incident("agent-fence-recovery")
    assert incident is not None
    assert incident.state.value == "contained"
    assert recovering.fences.get("agent-fence-recovery") is not None

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-fence-recovery")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.acquire_lease() is None

class FailingOnceFenceRegistry(RuntimeFenceRegistry):
    def __init__(self, path):
        super().__init__(path)
        self.fail_next_prepare = True

    def prepare(self, agent_id, containment_epoch):
        if self.fail_next_prepare:
            self.fail_next_prepare = False
            raise OSError("transient fence store failure")
        return super().prepare(agent_id, containment_epoch)


def test_fence_persistence_failure_still_contains_runtime_and_recovers_from_incident(
    tmp_path,
):
    incident_path = tmp_path / "incidents-fence-write-failure.json"
    fence_path = tmp_path / "fences-fence-write-failure.json"
    agent_id = "agent-fence-write-failure"
    service = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=FailingOnceFenceRegistry(fence_path),
    )
    runtime = service.register(agent_id)
    old_lease = runtime.acquire_lease()
    assert old_lease is not None

    report = service.contain(agent_id)

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert not runtime.lease_valid(old_lease)
    assert not report.durable
    assert "durable fence persistence unavailable" in report.persistence_failures[0]
    incident = service.incident(agent_id)
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert RuntimeFenceRegistry(fence_path).get(agent_id) is None

    # A fresh service reconstructs the missing fence from the durable incident.
    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    restarted_runtime = restarted.register(agent_id)
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted_runtime.epoch == 1
    assert restarted_runtime.acquire_lease() is None
    fence = restarted.fences.get(agent_id)
    assert fence is not None
    assert fence.containment_epoch == 1

class FailingMarkRecoveredRegistry(IncidentRegistry):
    def mark_recovered(self, incident_id):
        raise OSError("incident store unavailable during recovery")


def test_recovery_incident_write_failure_restores_fence_and_external_containment(
    tmp_path,
):
    incident_path = tmp_path / "incidents-recovery-write-failure.json"
    fence_path = tmp_path / "fences-recovery-write-failure.json"
    agent_id = "agent-recovery-incident-write-failure"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "recovery-write-failure-enforcer"

        def contain(self, _agent_id):
            external_state["contained"] = True
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

        def verify_contained(self, _agent_id):
            status = (
                EnforcementStatus.ENFORCED
                if external_state["contained"]
                else EnforcementStatus.VERIFICATION_FAILED
            )
            return EnforcementResult(self.name, status)

        def release(self, _agent_id):
            external_state["contained"] = False
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

        def verify_released(self, _agent_id):
            status = (
                EnforcementStatus.RELEASED
                if not external_state["contained"]
                else EnforcementStatus.VERIFICATION_FAILED
            )
            return EnforcementResult(self.name, status)

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    runtime = Runtime(agent_id)
    enforcer = StatefulEnforcer()
    service = ContainmentService(incidents=incidents, fences=fences)
    service.register(
        agent_id,
        containment=ContainmentController(runtime, enforcers=[enforcer]),
    )
    assert service.contain(agent_id).certified
    authorization = service.issue_recovery_authorization(agent_id)

    service.incidents = FailingMarkRecoveredRegistry(incident_path)
    with pytest.raises(
        RuntimeError, match="recovery aborted after incident persistence failure"
    ):
        service.recover(agent_id, authorization)

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    incident = IncidentRegistry(incident_path).latest_for_agent(agent_id)
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    fence = RuntimeFenceRegistry(fence_path).get(agent_id)
    assert fence is not None
    assert fence.containment_epoch == 1
    assert external_state["contained"] is True

