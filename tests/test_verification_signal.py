from agent_containment.models import Action, DecisionType
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
