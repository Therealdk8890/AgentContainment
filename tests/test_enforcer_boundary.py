from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.runtime import Runtime, RuntimeState


class RecordingEnforcer:
    name = "recording"

    def __init__(self, verify_status=EnforcementStatus.ENFORCED, release_verify_status=EnforcementStatus.RELEASED):
        self.calls = []
        self.verify_status = verify_status
        self.release_verify_status = release_verify_status

    def contain(self, agent_id):
        self.calls.append(("contain", agent_id))
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def release(self, agent_id):
        self.calls.append(("release", agent_id))
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)

    def verify_contained(self, agent_id):
        self.calls.append(("verify", agent_id))
        return EnforcementResult(self.name, self.verify_status)

    def verify_released(self, agent_id):
        self.calls.append(("verify_released", agent_id))
        return EnforcementResult(self.name, self.release_verify_status)


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


def test_release_result_and_verification_are_distinct():
    runtime = Runtime("agent-release-verified")
    enforcer = RecordingEnforcer()
    controller = ContainmentController(runtime, enforcers=[enforcer])

    controller.contain()
    failures = controller.release_enforcers()

    assert failures == ()
    assert enforcer.calls[-1] == ("verify_released", "agent-release-verified")


def test_failed_release_verification_is_fail_closed():
    runtime = Runtime("agent-release-verification-failure")
    enforcer = RecordingEnforcer(release_verify_status=EnforcementStatus.VERIFICATION_FAILED)
    controller = ContainmentController(runtime, enforcers=[enforcer])

    controller.contain()
    failures = controller.release_enforcers()

    assert failures
    assert any("release verification returned verification_failed" in failure for failure in failures)
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.can_execute is False
