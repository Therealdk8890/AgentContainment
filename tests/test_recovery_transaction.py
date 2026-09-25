from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementStatus
from agent_containment.runtime import Runtime, RuntimeState


def _result(status, detail=""):
    return type("Result", (), {"status": status, "detail": detail})()


class RecoveryTransactionEnforcer:
    name = "recovery-transaction"

    def __init__(self):
        self.released = False
        self.release_calls = 0
        self.contain_calls = 0

    def contain(self, agent_id):
        self.contain_calls += 1
        self.released = False
        return _result(EnforcementStatus.ENFORCED)

    def verify_contained(self, agent_id):
        return _result(EnforcementStatus.ENFORCED)

    def release(self, agent_id):
        self.release_calls += 1
        self.released = True
        return _result(EnforcementStatus.RELEASED)

    def verify_released(self, agent_id):
        return _result(EnforcementStatus.RELEASED)


def test_recovery_failure_recontains_external_enforcement():
    runtime = Runtime("agent-1")
    enforcer = RecoveryTransactionEnforcer()
    controller = ContainmentController(runtime, enforcers=[enforcer])

    controller.contain()
    epoch = runtime.epoch
    capability = runtime._rotate_recovery_capability()

    # Force the runtime transaction to reject recovery after external release.
    wrong_epoch = epoch + 1
    try:
        controller.recover(capability, wrong_epoch)
    except RuntimeError as exc:
        assert "contained runtime epoch mismatch" in str(exc)
    else:
        raise AssertionError("recovery must fail")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == epoch
    assert not runtime.can_execute
    assert enforcer.release_calls == 1
    assert enforcer.contain_calls == 2
    assert not enforcer.released



def test_failed_runtime_recovery_records_signed_evidence_and_recontainment():
    from agent_containment.proof_receipt import ReceiptVerifier

    runtime = Runtime("agent-2")
    enforcer = RecoveryTransactionEnforcer()
    controller = ContainmentController(runtime, enforcers=[enforcer])
    controller.contain()
    epoch = runtime.epoch
    capability = runtime._rotate_recovery_capability()

    try:
        controller.recover(capability, epoch + 1)
    except RuntimeError:
        pass
    else:
        raise AssertionError("recovery must fail")

    report = controller.last_recovery_report
    assert report is not None
    assert report.contained_epoch == epoch
    assert report.recovered_epoch is None
    assert report.events == (
        "recovery_requested",
        "external_release_verified",
        "runtime_recovery_failed",
        "recontainment_verified",
    )
    assert report.failures
    assert report.recontainment_failures == ()
    assert report.proof_status == "degraded"

    receipt = report.to_receipt(b"recovery-proof-secret", execution_id="exec-2")
    assert receipt.payload["recovery_result"] == "aborted"
    assert receipt.payload["events"] == list(report.events)
    assert ReceiptVerifier(b"recovery-proof-secret").verify(receipt)
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == epoch
    assert not runtime.can_execute


def test_successful_recovery_records_complete_evidence():
    runtime = Runtime("agent-3")
    enforcer = RecoveryTransactionEnforcer()
    controller = ContainmentController(runtime, enforcers=[enforcer])
    controller.contain()
    epoch = runtime.epoch
    capability = runtime._rotate_recovery_capability()

    recovered_epoch = controller.recover(capability, epoch)

    report = controller.last_recovery_report
    assert report is not None
    assert report.successful
    assert report.proof_status == "verified"
    assert report.recovered_epoch == recovered_epoch
    assert report.events == (
        "recovery_requested",
        "external_release_verified",
        "runtime_recovery_complete",
    )
