from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.evidence_chain import IncidentEvidenceChain
from agent_containment.governance_event import GovernanceEvent
from agent_containment.incident_evidence import IncidentEvidenceRecorder
from agent_containment.warden_observation import WardenObservation


def event(event_type="containment_requested"):
    return GovernanceEvent(
        event_id="evt-1",
        event_type=event_type,
        timestamp=100.0,
        agent_id="agent-1",
        trace_id="trace-1",
        run_id="run-1",
        action_id="action-1",
        policy_decision_id="decision-1",
        incident_id="incident-1",
        containment_epoch=7,
        reason="policy violation",
        attributes={"source": "controller"},
    )


def test_recorder_binds_controller_enforcement_and_warden():
    recorder = IncidentEvidenceRecorder(IncidentEvidenceChain())

    controller_node = recorder.record_governance_event(event())
    enforcement_node = recorder.record_enforcement_result(
        event(),
        EnforcementResult("cilium", EnforcementStatus.ENFORCED, "network deny active"),
    )
    observation = WardenObservation.from_governance_event(
        event("containment_observed"),
        observation_id="obs-1",
    )
    warden_node = recorder.record_warden_observation(observation)

    recorder.verify()

    assert controller_node.payload["source"] == "agent_containment.controller"
    assert enforcement_node.payload["provider"] == "cilium"
    assert enforcement_node.payload["enforced"] is True
    assert warden_node.payload["authority"] == "observation-only"
    assert recorder.chain.nodes[1].previous_hash == controller_node.node_hash
    assert recorder.chain.nodes[2].previous_hash == enforcement_node.node_hash


def test_enforcement_identity_is_stable():
    recorder = IncidentEvidenceRecorder(IncidentEvidenceChain())
    first = recorder.record_enforcement_result(
        event(),
        EnforcementResult("cilium", EnforcementStatus.ENFORCED, "blocked"),
    )
    recorder2 = IncidentEvidenceRecorder(IncidentEvidenceChain())
    second = recorder2.record_enforcement_result(
        event(),
        EnforcementResult("cilium", EnforcementStatus.ENFORCED, "blocked"),
    )
    assert first.event_id == second.event_id


def test_different_enforcement_result_cannot_alias():
    recorder = IncidentEvidenceRecorder(IncidentEvidenceChain())
    first = recorder.record_enforcement_result(
        event(),
        EnforcementResult("cilium", EnforcementStatus.ENFORCED, "blocked"),
    )
    second = recorder.record_enforcement_result(
        event(),
        EnforcementResult("cilium", EnforcementStatus.VERIFICATION_FAILED, "still active"),
    )
    assert first.event_id != second.event_id


def test_warden_observation_preserves_controller_identity():
    recorder = IncidentEvidenceRecorder(IncidentEvidenceChain())
    observation = WardenObservation.from_governance_event(
        event("containment_enforced"),
        observation_id="obs-123",
    )
    node = recorder.record_warden_observation(observation)

    assert node.payload["observed_event_id"] == "evt-1"
    assert node.incident_id == "incident-1"
    assert node.containment_epoch == 7
