from agent_containment.incident_state import IncidentRegistry, IncidentState


def test_containment_can_be_recorded_without_proof():
    registry = IncidentRegistry()
    incident = registry.record_containment(
        "inc-1", "agent-1", 7, reason="policy violation"
    )

    assert incident.state is IncidentState.CONTAINED
    assert incident.proof_attached is False


def test_proof_failure_marks_incident_degraded_without_changing_containment_epoch():
    registry = IncidentRegistry()
    registry.record_containment("inc-1", "agent-1", 7)

    degraded = registry.mark_proof_degraded("inc-1", reason="proof persistence unavailable")

    assert degraded.state is IncidentState.PROOF_DEGRADED
    assert degraded.containment_epoch == 7
    assert degraded.proof_attached is False
    assert degraded.proof_degraded_reason == "proof persistence unavailable"
    assert degraded.reason is None


def test_proof_can_be_attached_later_without_inventing_history():
    registry = IncidentRegistry()
    original = registry.record_containment("inc-1", "agent-1", 7, reason="containment")
    registry.mark_proof_degraded("inc-1", reason="DPK unavailable")

    recovered = registry.attach_proof("inc-1", "proof://sha256/abc")

    assert recovered.state is IncidentState.CONTAINED
    assert recovered.proof_attached is True
    assert recovered.proof_reference == "proof://sha256/abc"
    assert recovered.containment_epoch == original.containment_epoch
    assert recovered.created_at == original.created_at
    assert recovered.reason == original.reason
    assert recovered.proof_degraded_reason == "DPK unavailable"


def test_duplicate_incident_is_rejected():
    registry = IncidentRegistry()
    registry.record_containment("inc-1", "agent-1", 1)

    try:
        registry.record_containment("inc-1", "agent-1", 2)
    except ValueError:
        pass
    else:
        raise AssertionError("duplicate incident was accepted")
