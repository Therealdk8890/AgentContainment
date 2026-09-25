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
