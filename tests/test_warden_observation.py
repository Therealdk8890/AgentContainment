from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.governance_event import GovernanceEvent
from agent_containment.models import Action
from agent_containment.runtime import Runtime
from agent_containment.verification_signal import VerificationSignal
from agent_containment.warden_observation import WardenObservation
from agent_containment.warden_observer import WardenObserver


class RecordingEnforcer:
    name = "recording"

    def contain(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "boundary applied")

    def release(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)

    def verify_contained(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "boundary observed")

    def verify_released(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)


class FakeSupervisor:
    def create_agent(self, agent_id):
        return f"/controller/{agent_id}"

    def attach_pid(self, path, pid):
        return None


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
    observation = WardenObservation.from_governance_event(event, observation_id="obs-1")
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


def test_warden_observation_does_not_mutate_governance_event():
    attributes = {"external_verified": True}
    event = GovernanceEvent.create(
        event_id="event-2",
        event_type="authorization.allow",
        agent_id="agent-2",
        attributes=attributes,
    )
    observation = WardenObservation.from_governance_event(event, observation_id="obs-2")
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
    assert any(item.observed_event_type == "containment_enforced" for item in observations)
    assert all(item.agent_id == "agent-observed" for item in observations)
    assert service.status("agent-observed").value == "contained"
    assert not hasattr(observations[0], "authorize")
    assert not hasattr(observations[0], "contain")
    assert not hasattr(observations[0], "recover")


def test_warden_observer_is_one_way():
    observer = WardenObserver()
    event = GovernanceEvent.create(
        "event-1", "authorization_decision", "agent-1", action_id="action-1"
    )

    result = observer.observe(event)

    assert result.observed_event_id == "event-1"
    assert observer.snapshot() == (result,)
    assert not hasattr(observer, "authorize")
    assert not hasattr(observer, "contain")
    assert not hasattr(observer, "recover")


def test_real_controller_chain_is_reconstructable_by_warden():
    observer = WardenObserver()
    service = ContainmentService(
        cgroup_supervisor=FakeSupervisor(),
        event_sink=observer.observe,
    )
    service.register(
        "agent-1",
        containment=ContainmentController(
            Runtime("agent-1"),
            enforcers=[RecordingEnforcer()],
        ),
    )
    service.create_workload("agent-1")
    token = service.issue_identity_token("agent-1", peer_pid=1234)

    action = Action(
        agent_id="agent-1",
        action_id="action-1",
        operation="publish",
        resource="external-api",
        risk=1,
    )
    signal = VerificationSignal(
        disposition="block",
        report_fingerprint="sha256:report",
        policy_fingerprint="sha256:policy",
        blocking_claim_ids=("claim-1",),
        supported_claim_count=1,
        total_claim_count=1,
        trace_id="trace-1",
        run_id="run-1",
        action_id="action-1",
    )

    decision = service.authorize_verified(
        action,
        signal,
        identity_token=token,
        peer_pid=1234,
        cgroup_membership=lambda pid, path: pid == 1234 and path == "/controller/agent-1",
    )

    assert decision.decision.value == "halt"
    assert service.status("agent-1").value == "contained"

    events = observer.snapshot()
    types = [item.observed_event_type for item in events]
    assert "authorization_decision" in types
    assert "verification_evaluated" in types
    assert "containment_requested" in types
    assert "containment_enforced" in types
    assert "containment_certified" in types

    correlated = [
        item for item in events
        if item.action_id == "action-1" or item.trace_id == "trace-1"
    ]
    assert correlated
    assert any(item.policy_decision_id == "action-1" for item in correlated)

    assert not hasattr(observer, "authorize")
    assert not hasattr(observer, "contain")
    assert not hasattr(observer, "release")
    assert not hasattr(observer, "recover")
