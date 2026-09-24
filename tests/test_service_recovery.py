from agent_containment.audit import AuditLog
from agent_containment.control import ContainmentService
from agent_containment.incident_state import IncidentRegistry, IncidentState


def test_containment_returns_even_when_audit_persistence_is_degraded(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    incident_path = tmp_path / "incidents.json"
    audit = AuditLog(audit_path)
    incidents = IncidentRegistry(incident_path)
    service = ContainmentService(audit=audit, incidents=incidents)
    service.register("agent-1")

    # Simulate an audit/proof store becoming corrupt after registration.
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
