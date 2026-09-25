from agent_containment import GovernanceEvent
from agent_containment.control import ContainmentService


def test_governance_event_serialization_is_stable():
    event = GovernanceEvent(
        event_id="evt-1",
        event_type="authorization_decision",
        timestamp=1.0,
        agent_id="agent-1",
        action_id="action-1",
        policy_decision_id="decision-1",
        attributes={"decision": "allow"},
    )

    assert event.to_dict()["attributes"] == {"decision": "allow"}
    assert event.to_json() == '{"action_id":"action-1","agent_id":"agent-1","attributes":{"decision":"allow"},"containment_epoch":null,"event_id":"evt-1","event_type":"authorization_decision","incident_id":null,"policy_decision_id":"decision-1","reason":null,"run_id":null,"timestamp":1.0,"trace_id":null}'


def test_containment_emits_controller_lifecycle_events():
    events = []
    service = ContainmentService(event_sink=events.append)
    service.register("agent-1")

    report = service.contain("agent-1")
    assert report.complete

    types = [event.event_type for event in events]
    assert types == [
        "agent_registered",
        "containment_requested",
        "capability_revoked",
        "containment_enforced",
        "containment_certified",
    ]
    assert events[1].incident_id == "agent-1:containment:1"
    assert events[-1].containment_epoch == 1


def test_failing_event_sink_does_not_block_containment():
    def broken_sink(event):
        raise RuntimeError("sink unavailable")

    service = ContainmentService(event_sink=broken_sink)
    service.register("agent-1")
    report = service.contain("agent-1")

    assert report.complete
    assert service.status("agent-1").value == "contained"
