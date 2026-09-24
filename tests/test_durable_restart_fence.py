import pytest

from agent_containment.control import ContainmentService
from agent_containment.incident_state import IncidentRegistry
from agent_containment.runtime import RuntimeState


class FailingIncidentRegistry(IncidentRegistry):
    def record_containment(self, *args, **kwargs):
        raise OSError("incident store unavailable")


def test_restart_stays_contained_when_incident_persistence_fails(tmp_path):
    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"

    first = ContainmentService(
        incidents=FailingIncidentRegistry(incident_path),
        fences=__import__("agent_containment.runtime_fence", fromlist=["RuntimeFenceRegistry"]).RuntimeFenceRegistry(fence_path),
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

    from agent_containment.runtime_fence import RuntimeFenceRegistry

    first_fences = RuntimeFenceRegistry(fence_path)
    first_fences.prepare("agent-fence-only", 1)

    restarted = ContainmentService(
        incidents=IncidentRegistry(tmp_path / "incidents.json"),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-fence-only")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert restarted.incident("agent-fence-only") is None
    assert runtime.acquire_lease() is None


def test_recovery_does_not_clear_fence_if_fence_persistence_fails(tmp_path):
    from agent_containment.runtime_fence import RuntimeFenceRegistry

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
    assert recovering.recover("agent-fence-recovery", authorization) == 2

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-fence-recovery")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.acquire_lease() is None
