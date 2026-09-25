from agent_containment.models import Action, Decision, DecisionType
from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.verification_signal import VerificationSignal, decision_from_verification


def signal(**overrides):
    value = {
        "disposition": "block",
        "reportFingerprint": "report-1",
        "policyFingerprint": "policy-1",
        "blockingClaimIDs": ["claim-1"],
        "supportedClaimCount": 0,
        "totalClaimCount": 1,
        "actionID": "action-1",
    }
    value.update(overrides)
    return VerificationSignal.from_mapping(value)


def test_block_signal_becomes_controller_halt():
    decision = decision_from_verification(
        Action("agent-1", "action-1", "publish", "memo"),
        signal(),
    )
    assert decision.decision is DecisionType.HALT


def test_review_signal_becomes_controller_pause():
    decision = decision_from_verification(
        Action("agent-1", "action-1", "publish", "memo"),
        signal(disposition="requireReview"),
    )
    assert decision.decision is DecisionType.PAUSE


def test_mismatched_action_is_denied():
    decision = decision_from_verification(
        Action("agent-1", "action-2", "publish", "memo"),
        signal(),
    )
    assert decision.decision is DecisionType.DENY


def test_verified_block_enters_durable_containment_and_emits_linked_events():
    events = []
    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService(
        event_sink=events.append,
    )

    class VerifiedEnforcer:
        name = "test-external"

        def contain(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

        def verify_contained(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

        def release(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

        def verify_released(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

    runtime = service.register("agent-1")
    service.configure_containment("agent-1", ContainmentController(runtime, enforcers=[VerifiedEnforcer()]))
    service.authorize = lambda action, **kwargs: Decision(action.action_id, DecisionType.ALLOW, "test authorization")
    action = Action("agent-1", "action-1", "publish", "memo")
    decision = service.authorize_verified(
        action,
        signal(
            traceID="trace-1",
            runID="run-1",
            reportFingerprint="report-blocked",
            policyFingerprint="policy-1",
        ),
    )

    assert decision.decision is DecisionType.HALT
    assert service.status("agent-1").value == "contained"
    incident = service.incident("agent-1")
    assert incident is not None
    assert incident.incident_id == "agent-1:containment:1"

    verification = [event for event in events if event.event_type == "verification_evaluated"]
    assert len(verification) == 1
    assert verification[0].trace_id == "trace-1"
    assert verification[0].run_id == "run-1"
    assert verification[0].action_id == "action-1"
    assert verification[0].attributes["report_fingerprint"] == "report-blocked"

    assert [event.event_type for event in events][-4:] == [
        "containment_requested",
        "capability_revoked",
        "containment_enforced",
        "containment_certified",
    ]


def test_verified_review_does_not_contain():
    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService()
    service.register("agent-1")
    action = Action("agent-1", "action-1", "publish", "memo")

    service.authorize = lambda action, **kwargs: Decision(action.action_id, DecisionType.ALLOW, "test authorization")
    decision = service.authorize_verified(
        action,
        signal(disposition="requireReview"),
    )

    assert decision.decision is DecisionType.PAUSE
    assert service.status("agent-1").value == "active"
    assert service.incident("agent-1") is None


def test_verification_cannot_override_base_policy_deny():
    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService()
    service.register("agent-1")
    action = Action("agent-1", "action-1", "read", "workspace", risk=99)

    decision = service.authorize_verified(
        action,
        signal(disposition="allow"),
    )

    assert decision.decision is DecisionType.DENY
    assert service.status("agent-1").value == "active"


def test_mapping_parser_rejects_type_coercion_at_security_boundary():
    for key, value in (("version", "1"), ("supportedClaimCount", "1"), ("totalClaimCount", True), ("reportFingerprint", 123)):
        payload = {
            "disposition": "allow",
            "reportFingerprint": "report-1",
            "policyFingerprint": "policy-1",
            "totalClaimCount": 0,
        }
        payload[key] = value
        try:
            VerificationSignal.from_mapping(payload)
        except ValueError:
            pass
        else:
            raise AssertionError(f"expected strict rejection for {key}")


def test_mapping_parser_rejects_present_optional_ids_with_wrong_type():
    payload = {
        "disposition": "allow",
        "reportFingerprint": "report-1",
        "policyFingerprint": "policy-1",
        "traceID": 123,
    }
    try:
        VerificationSignal.from_mapping(payload)
    except ValueError:
        pass
    else:
        raise AssertionError("expected invalid traceID to be rejected")



def test_shared_v1_fixture_parses_as_verification_signal():
    import json
    from pathlib import Path

    fixture = Path(__file__).parent / "fixtures" / "governance-verification-signal-v1.json"
    signal = VerificationSignal.from_mapping(json.loads(fixture.read_text(encoding="utf-8")))

    assert signal.version == 1
    assert signal.disposition == "block"
    assert signal.report_fingerprint == "report-123"
    assert signal.policy_fingerprint == "policy-123"
    assert signal.blocking_claim_ids == ("claim-unsafe",)
    assert signal.review_claim_ids == ()
    assert signal.supported_claim_count == 0
    assert signal.total_claim_count == 1
    assert signal.trace_id == "trace-1"
    assert signal.run_id == "run-1"
    assert signal.action_id == "action-1"


def test_containment_without_external_verification_is_not_certified():
    events = []
    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService(
        event_sink=events.append,
    )
    service.register("agent-local")
    report = service.contain("agent-local")

    assert report.complete
    assert not report.external_verified
    assert not report.certified
    assert service.status("agent-local").value == "contained"
    assert not any(event.event_type == "containment_certified" for event in events)
    failed = [event for event in events if event.event_type == "containment_verification_failed"]
    assert len(failed) == 1
    assert failed[0].attributes["external_verified"] is False


def test_lying_external_enforcer_prevents_certification():
    events = []

    class LyingEnforcer:
        name = "lying"

        def contain(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

        def verify_contained(self, agent_id):
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                "process still executable",
            )

        def release(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

        def verify_released(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService(
        event_sink=events.append,
    )
    runtime = service.register("agent-lying")
    service.configure_containment(
        "agent-lying",
        ContainmentController(runtime, enforcers=[LyingEnforcer()]),
    )

    report = service.contain("agent-lying")

    assert report.complete is False
    assert report.external_verified is False
    assert report.certified is False
    assert service.status("agent-lying").value == "contained"
    assert not any(event.event_type == "containment_certified" for event in events)
    failed = [event for event in events if event.event_type == "containment_verification_failed"]
    assert len(failed) == 1
    assert "process still executable" in failed[0].attributes["failures"][0]


def test_review_timeout_never_grants_execution_and_can_escalate():
    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService(
        review_timeout_seconds=0.001,
    )
    service.register("agent-review")
    service.authorize = lambda action, **kwargs: Decision(action.action_id, DecisionType.ALLOW, "test authorization")
    action = Action("agent-review", "review-action", "publish", "memo")

    decision = service.authorize_verified(action, signal(disposition="requireReview", actionID="review-action"))
    assert decision.decision is DecisionType.PAUSE

    review_events = []
    service.event_sink = review_events.append
    review = next(iter(service._reviews.values()))
    import time
    time.sleep(0.01)

    assert service.review(review.review_id).state.value == "expired"
    with __import__("pytest").raises(RuntimeError, match="review has expired"):
        service.approve_review(review.review_id)

    escalation = service.escalate_review(review.review_id)
    assert escalation.decision is DecisionType.HALT
    assert service.status("agent-review").value == "contained"
    assert service.incident("agent-review") is not None
    assert any(event.event_type == "review_escalated" for event in review_events)


def test_pending_review_can_be_approved_without_containment():
    service = __import__("agent_containment.control", fromlist=["ContainmentService"]).ContainmentService(
        review_timeout_seconds=60,
    )
    service.register("agent-review-ok")
    service.authorize = lambda action, **kwargs: Decision(action.action_id, DecisionType.ALLOW, "test authorization")
    action = Action("agent-review-ok", "review-action", "publish", "memo")

    decision = service.authorize_verified(action, signal(disposition="requireReview", actionID="review-action"))
    assert decision.decision is DecisionType.PAUSE
    review = next(iter(service._reviews.values()))

    approved = service.approve_review(review.review_id)
    assert approved.decision is DecisionType.ALLOW
    assert service.status("agent-review-ok").value == "active"
    assert service.incident("agent-review-ok") is None
