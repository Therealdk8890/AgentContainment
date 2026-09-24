import pytest

from agent_containment.audit import AuditLog
from agent_containment.control import ContainmentService
from agent_containment.containment import ContainmentController
from agent_containment.incident_state import IncidentRegistry, IncidentState
from agent_containment.runtime import Runtime, RuntimeState


def test_containment_returns_even_when_audit_persistence_is_degraded(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    incident_path = tmp_path / "incidents.json"
    audit = AuditLog(audit_path)
    incidents = IncidentRegistry(incident_path)
    service = ContainmentService(audit=audit, incidents=incidents)
    service.register("agent-1")

    audit_path.write_text("{corrupt", encoding="utf-8")

    report = service.contain("agent-1")
    incident = service.incident("agent-1")

    assert report.epoch == 1
    assert report.complete
    assert incident is not None
    assert incident.state is IncidentState.PROOF_DEGRADED
    assert incident.containment_epoch == 1

    recovered = IncidentRegistry(incident_path).get(incident.incident_id)
    assert recovered is not None
    assert recovered.state is IncidentState.PROOF_DEGRADED
    assert recovered.containment_epoch == 1


def test_missing_audit_history_does_not_create_incident_history(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(audit=None, incidents=incidents)
    service.register("agent-2")

    assert service.incident("agent-2") is None


def test_restart_restores_durable_containment_as_an_admission_fence(tmp_path):
    incident_path = tmp_path / "incidents.json"
    incidents = IncidentRegistry(incident_path)

    first = ContainmentService(incidents=incidents)
    first.register("agent-restart")
    lease = first._managed("agent-restart").runtime.acquire_lease()
    assert lease is not None
    report = first.contain("agent-restart")
    assert report.epoch == 1

    recovered_incidents = IncidentRegistry(incident_path)
    second = ContainmentService(incidents=recovered_incidents)
    runtime = second.register("agent-restart")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert runtime.acquire_lease() is None
    assert runtime.execute_if_active(lease, lambda: "unsafe") is None


def test_restart_rejects_an_executable_supplied_runtime_when_contained(tmp_path):
    incident_path = tmp_path / "incidents.json"
    incidents = IncidentRegistry(incident_path)

    first = ContainmentService(incidents=incidents)
    first.register("agent-supplied")
    first.contain("agent-supplied")

    recovered = ContainmentService(incidents=IncidentRegistry(incident_path))
    executable_runtime = Runtime("agent-supplied")

    with pytest.raises(RuntimeError, match="durable containment state"):
        recovered.register(
            "agent-supplied",
            containment=ContainmentController(executable_runtime),
        )


def test_corrupt_incident_registry_fails_closed(tmp_path):
    incident_path = tmp_path / "incidents.json"
    incident_path.write_text("{corrupt", encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid incident registry"):
        ContainmentService(incidents=IncidentRegistry(incident_path))
