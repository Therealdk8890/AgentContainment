from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.evidence_chain import IncidentEvidenceChain


def test_post_containment_activity_is_distinguishable_from_successful_enforcement():
    chain = IncidentEvidenceChain()
    chain.append("contain", "containment.requested", 10.0, "agent-1", "inc-1", 4, {})
    chain.append("enforce", "enforcement.containment.enforced", 11.0, "agent-1", "inc-1", 4,
                 {"status": "enforced", "provider": "cilium"})
    chain.append("obs", "warden.agent_action", 12.0, "agent-1", "inc-1", 4,
                 {"authority": "observation-only", "post_containment": True})
    assert chain.verify() is None
    assert chain.nodes[-1].event_type == "warden.agent_action"


def test_verification_failure_remains_evidence_not_success():
    chain = IncidentEvidenceChain()
    result = EnforcementResult("cilium", EnforcementStatus.VERIFICATION_FAILED, "agent still active")
    chain.append("verify", "enforcement.containment.verification_failed", 20.0,
                 "agent-1", "inc-1", 8, {"status": result.status.value, "enforced": result.enforced})
    assert chain.nodes[0].payload["enforced"] is False
    assert chain.nodes[0].payload["status"] == "verification_failed"


def test_stale_epoch_is_not_silently_rewritten():
    chain = IncidentEvidenceChain()
    chain.append("e1", "containment.requested", 10.0, "agent-1", "inc-1", 9, {})
    chain.append("e2", "recovery.authorized", 11.0, "agent-1", "inc-1", 8,
                 {"authorization_epoch": 8})
    chain.verify()
    assert chain.nodes[1].containment_epoch == 8
    assert chain.nodes[1].payload["authorization_epoch"] == 8


def test_duplicate_event_ids_are_visible_as_duplicate_evidence():
    chain = IncidentEvidenceChain()
    chain.append("same", "action", 10.0, "agent-1", "inc-1", 1, {"n": 1})
    chain.append("same", "action.replay", 11.0, "agent-1", "inc-1", 1, {"n": 2})
    chain.verify()
    assert [n.event_id for n in chain.nodes] == ["same", "same"]


def test_downstream_chain_failure_does_not_mutate_source_result():
    result = EnforcementResult("cilium", EnforcementStatus.ENFORCED, "deny active")
    chain = IncidentEvidenceChain()
    try:
        chain.append("", "enforcement", 1.0, "agent-1", "inc-1", 1, {})
    except ValueError:
        pass
    assert result.status is EnforcementStatus.ENFORCED
    assert result.enforced is True
