import pytest

from agent_containment.control import ContainmentService
from agent_containment.incident_state import IncidentRegistry
from agent_containment.runtime import RuntimeState
from agent_containment.runtime_fence import RuntimeFenceRegistry


class FailingIncidentRegistry(IncidentRegistry):
    def record_containment(self, *args, **kwargs):
        raise OSError("incident store unavailable")


def test_restart_stays_contained_when_incident_persistence_fails(tmp_path):
    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"

    first = ContainmentService(
        incidents=FailingIncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    first.register("agent-persistence-failure")

    report = first.contain("agent-persistence-failure")

    assert first.status("agent-persistence-failure") is RuntimeState.CONTAINED
    assert not report.durable
    assert "incident persistence unavailable" in report.persistence_failures[0]

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=__import__("agent_containment.runtime_fence", fromlist=["RuntimeFenceRegistry"]).RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-persistence-failure")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert runtime.acquire_lease() is None


def test_durable_fence_blocks_restart_even_without_incident_record(tmp_path):
    fence_path = tmp_path / "fences.json"

    first_fences = RuntimeFenceRegistry(fence_path)
    first_fences.prepare("agent-fence-only", 1)

    restarted = ContainmentService(
        incidents=IncidentRegistry(tmp_path / "incidents.json"),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-fence-only")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert restarted.incident("agent-fence-only") is None
    assert runtime.acquire_lease() is None


def test_recovery_does_not_clear_fence_if_fence_persistence_fails(tmp_path):
    class FailingClearFenceRegistry(RuntimeFenceRegistry):
        def clear(self, agent_id):
            raise OSError("fence store unavailable")

    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"

    fences = RuntimeFenceRegistry(fence_path)
    service = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=fences,
    )
    service.register("agent-fence-recovery")
    service.contain("agent-fence-recovery")

    recovering = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=FailingClearFenceRegistry(fence_path),
    )
    recovering.register("agent-fence-recovery")
    authorization = recovering.issue_recovery_authorization("agent-fence-recovery")

    with pytest.raises(RuntimeError, match="durable recovery fence could not be cleared"):
        recovering.recover("agent-fence-recovery", authorization)

    assert recovering.status("agent-fence-recovery") is RuntimeState.CONTAINED
    incident = recovering.incident("agent-fence-recovery")
    assert incident is not None
    assert incident.state.value == "contained"
    assert recovering.fences.get("agent-fence-recovery") is not None

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = restarted.register("agent-fence-recovery")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.acquire_lease() is None


def test_restart_reconciles_after_crash_after_external_release(tmp_path):
    """A crash after release but before durable recovery must fail closed."""
    from agent_containment.containment import ContainmentController
    from agent_containment.enforcer import EnforcementStatus
    from agent_containment.runtime import Runtime

    class SharedEnforcer:
        name = "shared-recovery-boundary"

        def __init__(self):
            self.released = False
            self.contain_calls = 0
            self.release_calls = 0

        def contain(self, agent_id):
            self.contain_calls += 1
            self.released = False
            return type("Result", (), {
                "status": EnforcementStatus.ENFORCED,
                "detail": "",
            })()

        def verify_contained(self, agent_id):
            return type("Result", (), {
                "status": EnforcementStatus.ENFORCED,
                "detail": "",
            })()

        def release(self, agent_id):
            self.release_calls += 1
            self.released = True
            return type("Result", (), {
                "status": EnforcementStatus.RELEASED,
                "detail": "",
            })()

        def verify_released(self, agent_id):
            return type("Result", (), {
                "status": EnforcementStatus.RELEASED,
                "detail": "",
            })()

    class CrashAfterReleaseRegistry(IncidentRegistry):
        def mark_recovered(self, incident_id):
            raise SystemExit("simulated controller crash")

    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"
    enforcer = SharedEnforcer()

    first = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    first.register(
        "agent-recovery-crash",
        containment=ContainmentController(
            Runtime("agent-recovery-crash"),
            enforcers=[enforcer],
        ),
    )
    first.contain("agent-recovery-crash")
    assert enforcer.contain_calls == 1

    crashing = ContainmentService(
        incidents=CrashAfterReleaseRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    runtime = Runtime("agent-recovery-crash")
    runtime.restore_contained(1)
    crashing.register(
        "agent-recovery-crash",
        containment=ContainmentController(runtime, enforcers=[enforcer]),
    )
    authorization = crashing.issue_recovery_authorization("agent-recovery-crash")

    with pytest.raises(SystemExit, match="simulated controller crash"):
        crashing.recover("agent-recovery-crash", authorization)

    # The crash window is intentionally before durable RECOVERED state.
    assert enforcer.released
    assert crashing.fences.get("agent-recovery-crash") is None
    assert crashing.incident("agent-recovery-crash").state.value == "contained"

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    restarted_runtime = Runtime("agent-recovery-crash")
    restarted_runtime.restore_contained(1)
    restarted.register(
        "agent-recovery-crash",
        containment=ContainmentController(
            restarted_runtime,
            enforcers=[enforcer],
        ),
    )

    # Recovery authorization must reconcile and re-establish the external
    # containment boundary before any new authorization is issued.
    before = enforcer.contain_calls
    fresh_authorization = restarted.issue_recovery_authorization("agent-recovery-crash")
    assert enforcer.contain_calls == before + 1
    assert not enforcer.released
    assert restarted.fences.get("agent-recovery-crash") is None

    assert restarted.recover("agent-recovery-crash", fresh_authorization) == 2
    assert restarted_runtime.state.value == "active"
