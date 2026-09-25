from agent_containment.control import ContainmentService
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
    assert not hasattr(observation, "authorize")
    assert not hasattr(observation, "contain")
    assert not hasattr(observation, "release")
    assert not hasattr(observation, "recover")
    assert set(value) == {
        "version",
        "observation_id",
        "observed_event_id",
        "observed_event_type",
        "observed_at",
        "agent_id",
        "trace_id",
        "run_id",
        "action_id",
        "policy_decision_id",
        "incident_id",
        "containment_epoch",
        "reason",
        "attributes",
        "authority",
    }


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


def test_warden_can_observe_controller_events_without_receiving_controller_authority():
    observations = []

    def observe(event):
        observations.append(
            WardenObservation.from_governance_event(
                event, observation_id=f"obs:{len(observations) + 1}"
            )
        )

    service = ContainmentService(event_sink=observe)
    service.register("agent-observed")
    report = service.contain("agent-observed")

    assert report.certified or report.complete
    assert observations
    assert any(
        item.observed_event_type == "containment_enforced"
        for item in observations
    )
    assert all(item.agent_id == "agent-observed" for item in observations)
    assert service.status("agent-observed").value == "contained"
    assert not hasattr(observations[0], "authorize")
    assert not hasattr(observations[0], "contain")
    assert not hasattr(observations[0], "recover")
