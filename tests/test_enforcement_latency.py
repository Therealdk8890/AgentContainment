from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.runtime import Runtime


class RecordingEnforcer:
    name = "recording"

    def __init__(self):
        self.applied = False

    def contain(self, agent_id):
        self.applied = True
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def verify_contained(self, agent_id):
        assert self.applied
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def release(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)

    def verify_released(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)


def test_containment_records_provider_and_independent_verification_times():
    enforcer = RecordingEnforcer()
    controller = ContainmentController(Runtime("latency-agent"), enforcers=[enforcer])

    report = controller.contain()

    assert report.certified
    assert report.containment_requested_at is not None
    assert report.provider_applied_at is not None
    assert report.independently_verified_at is not None
    assert report.containment_requested_at <= report.provider_applied_at
    assert report.provider_applied_at <= report.independently_verified_at
    assert report.enforcement_latency_seconds is not None
    assert report.enforcement_latency_seconds >= 0
