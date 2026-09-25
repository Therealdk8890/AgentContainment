from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementStatus
from agent_containment.runtime import Runtime, RuntimeState


def _result(status, detail=""):
    return type("Result", (), {"status": status, "detail": detail})()


class FailingReleaseEnforcer:
    name = "failing-release"

    def __init__(self):
        self.contain_calls = 0
        self.release_calls = 0

    def contain(self, agent_id):
        self.contain_calls += 1
        return _result(EnforcementStatus.ENFORCED)

    def verify_contained(self, agent_id):
        return _result(EnforcementStatus.ENFORCED)

    def release(self, agent_id):
        self.release_calls += 1
        return _result(EnforcementStatus.DEGRADED, "release interrupted")

    def verify_released(self, agent_id):
        raise AssertionError("must not verify a failed release")


def test_recovery_aborts_on_partial_external_release():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime, enforcers=[FailingReleaseEnforcer()])
    controller.contain()
    capability = runtime._rotate_recovery_capability()
    epoch = runtime.epoch

    try:
        controller.recover(capability, epoch)
    except RuntimeError as exc:
        assert "recovery aborted" in str(exc)
    else:
        raise AssertionError("recovery must fail closed")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == epoch
    assert not runtime.can_execute
