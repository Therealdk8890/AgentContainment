from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementStatus
from agent_containment.proof_receipt import ReceiptVerifier
from agent_containment.runtime import Runtime


SECRET = b"containment-receipt-secret"


class VerifiedEnforcer:
    name = "test-provider"

    def contain(self, agent_id):
        return type("Result", (), {"status": EnforcementStatus.ENFORCED, "detail": ""})()

    def verify_contained(self, agent_id):
        return type("Result", (), {"status": EnforcementStatus.ENFORCED, "detail": ""})()

    def release(self, agent_id):
        return type("Result", (), {"status": EnforcementStatus.RELEASED, "detail": ""})()

    def verify_released(self, agent_id):
        return type("Result", (), {"status": EnforcementStatus.RELEASED, "detail": ""})()


def test_containment_report_produces_verifiable_receipt():
    controller = ContainmentController(
        Runtime("agent-1"),
        enforcers=[VerifiedEnforcer()],
    )
    report = controller.contain()

    receipt = report.to_receipt(
        SECRET,
        execution_id="exec-1",
        policy_id="policy-abc",
    )

    assert receipt.payload["agent_id"] == "agent-1"
    assert receipt.payload["epoch"] == report.epoch
    assert receipt.payload["proof_status"] == "verified"
    assert "runtime_fenced" in receipt.payload["stages"]
    assert receipt.verify(SECRET)
    assert ReceiptVerifier(SECRET).verify(receipt)


def test_degraded_report_produces_degraded_receipt():
    report = ContainmentController(Runtime("agent-2")).contain()

    receipt = report.to_receipt(SECRET, execution_id="exec-2")

    assert report.certified is False
    assert receipt.payload["proof_status"] == "degraded"
    assert receipt.verify(SECRET)
