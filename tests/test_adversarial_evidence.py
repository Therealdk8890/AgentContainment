from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.evidence_chain import IncidentEvidenceChain


def test_post_containment_activity_is_distinguishable_from_successful_enforcement():
    chain = IncidentEvidenceChain()
    chain.append(event_id="contain", event_type="containment.requested", timestamp=10.0,
                 agent_id="agent-1", incident_id="inc-1", containment_epoch=4, payload={})
    chain.append(event_id="enforce", event_type="enforcement.containment.enforced", timestamp=11.0,
                 agent_id="agent-1", incident_id="inc-1", containment_epoch=4,
                 payload={"status": "enforced", "provider": "cilium"})
    chain.append(event_id="obs", event_type="warden.agent_action", timestamp=12.0,
                 agent_id="agent-1", incident_id="inc-1", containment_epoch=4,
                 payload={"authority": "observation-only", "post_containment": True})
    chain.verify()
    assert chain.nodes[-1].event_type == "warden.agent_action"


def test_verification_failure_remains_evidence_not_success():
    chain = IncidentEvidenceChain()
    result = EnforcementResult("cilium", EnforcementStatus.VERIFICATION_FAILED, "agent still active")
    chain.append(event_id="verify", event_type="enforcement.containment.verification_failed",
                 timestamp=20.0, agent_id="agent-1", incident_id="inc-1", containment_epoch=8,
                 payload={"status": result.status.value, "enforced": result.enforced})
    assert chain.nodes[0].payload["enforced"] is False
    assert chain.nodes[0].payload["status"] == "verification_failed"


def test_stale_epoch_is_not_silently_rewritten():
    chain = IncidentEvidenceChain()
    chain.append(event_id="e1", event_type="containment.requested", timestamp=10.0,
                 agent_id="agent-1", incident_id="inc-1", containment_epoch=9, payload={})
    chain.append(event_id="e2", event_type="recovery.authorized", timestamp=11.0,
                 agent_id="agent-1", incident_id="inc-1", containment_epoch=8,
                 payload={"authorization_epoch": 8})
    chain.verify()
    assert chain.nodes[1].containment_epoch == 8
    assert chain.nodes[1].payload["authorization_epoch"] == 8


def test_duplicate_event_ids_are_rejected_on_ingest():
    chain = IncidentEvidenceChain()
    chain.append(event_id="same", event_type="action", timestamp=10.0,
                 agent_id="agent-1", incident_id="inc-1", containment_epoch=1, payload={"n": 1})
    try:
        chain.append(event_id="same", event_type="action.replay", timestamp=11.0,
                     agent_id="agent-1", incident_id="inc-1", containment_epoch=1, payload={"n": 2})
    except ValueError as exc:
        assert "duplicate evidence event_id" in str(exc)
    else:
        raise AssertionError("duplicate event_id was accepted")


def test_duplicate_event_ids_are_detected_if_chain_is_tampered():
    chain = IncidentEvidenceChain()
    first = chain.append(event_id="one", event_type="action", timestamp=10.0,
                         agent_id="agent-1", incident_id="inc-1", containment_epoch=1, payload={})
    second = chain.append(event_id="two", event_type="action", timestamp=11.0,
                          agent_id="agent-1", incident_id="inc-1", containment_epoch=1, payload={})
    chain._nodes[1] = second.__class__(
        sequence=second.sequence, event_id=first.event_id, event_type=second.event_type,
        timestamp=second.timestamp, agent_id=second.agent_id, incident_id=second.incident_id,
        containment_epoch=second.containment_epoch, payload=second.payload,
        previous_hash=second.previous_hash, node_hash=second.node_hash,
    )
    try:
        chain.verify()
    except ValueError as exc:
        assert "duplicate evidence event_id" in str(exc)
    else:
        raise AssertionError("tampered duplicate identity was not detected")


def test_downstream_chain_failure_does_not_mutate_source_result():
    result = EnforcementResult("cilium", EnforcementStatus.ENFORCED, "deny active")
    chain = IncidentEvidenceChain()
    try:
        chain.append(event_id="", event_type="enforcement", timestamp=1.0,
                     agent_id="agent-1", incident_id="inc-1", containment_epoch=1, payload={})
    except ValueError:
        pass
    assert result.status is EnforcementStatus.ENFORCED
    assert result.enforced is True
