from agent_containment.governance_event import GovernanceEvent
from agent_containment.warden_observation import WardenObservation


def test_warden_observation_is_observation_only():
    event = GovernanceEvent.create(
        event_id="event-1",
        event_type="containment.certified",
        agent_id="agent-1",
        trace_id="trace-1",
        run_id="run-1",
        action_id="action-1",
        containment_epoch=7,
        reason="external enforcement verified",
        attributes={"external_verified": True},
    )

    observation = WardenObservation.from_governance_event(
        event, observation_id="obs-1"
    )
    value = observation.to_dict()

    assert value["observed_event_id"] == "event-1"
    assert value["observed_event_type"] == "containment.certified"
    assert value["containment_epoch"] == 7
    assert value["authority"] == "observation-only"
    assert value["attributes"]["external_verified"] is True
    assert "authorize" not in value
    assert "contain" not in value
    assert "recover" not in value


def test_warden_observation_does_not_mutate_governance_event():
    attributes = {"external_verified": True}
    event = GovernanceEvent.create(
        event_id="event-2",
        event_type="authorization.allow",
        agent_id="agent-2",
        attributes=attributes,
    )

    observation = WardenObservation.from_governance_event(
        event, observation_id="obs-2"
    )
    observation.attributes["external_verified"] = False

    assert event.attributes["external_verified"] is True
    assert observation.attributes["external_verified"] is False
