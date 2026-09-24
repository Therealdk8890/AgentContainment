from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.runtime import Runtime, RuntimeState


class RecordingEnforcer:
    name = "recording"

    def __init__(self, verify_status=EnforcementStatus.ENFORCED):
        self.calls = []
        self.verify_status = verify_status

    def contain(self, agent_id):
        self.calls.append(("contain", agent_id))
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def release(self, agent_id):
        self.calls.append(("release", agent_id))
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def verify_contained(self, agent_id):
        self.calls.append(("verify", agent_id))
        return EnforcementResult(self.name, self.verify_status)


class FailingReleaseEnforcer(RecordingEnforcer):
    def release(self, agent_id):
        self.calls.append(("release", agent_id))
        return EnforcementResult(
            self.name,
            EnforcementStatus.DEGRADED,
            "provider refused release",
        )


def test_containment_verifies_external_enforcement():
    runtime = Runtime("agent-enforcer")
    enforcer = RecordingEnforcer()
    controller = ContainmentController(runtime, enforcers=[enforcer])

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert report.complete
    assert "enforcer:recording:verified" in report.stages
    assert enforcer.calls == [
        ("contain", "agent-enforcer"),
        ("verify", "agent-enforcer"),
    ]


def test_failed_verification_degrades_containment_without_reopening_runtime():
    runtime = Runtime("agent-verification-failure")
    enforcer = RecordingEnforcer(EnforcementStatus.VERIFICATION_FAILED)
    controller = ContainmentController(runtime, enforcers=[enforcer])

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert not report.complete
    assert any("verification_failed" in failure for failure in report.failures)


def test_recovery_release_failure_is_fail_closed():
    runtime = Runtime("agent-release-failure")
    enforcer = FailingReleaseEnforcer()
    controller = ContainmentController(runtime, enforcers=[enforcer])

    controller.contain()
    failures = controller.release_enforcers()

    assert failures
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.can_execute is False
