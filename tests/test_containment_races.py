import threading

import pytest

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.runtime import Runtime, RuntimeState


THREAD_TIMEOUT = 2


def test_stale_lease_is_invalid_after_containment():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime)
    gateway = ActionGateway(PolicyEngine(), controller)

    lease = gateway.acquire_lease()
    assert lease is not None
    controller.contain()

    result = gateway.execute_with_lease(
        Action("agent-1", "a1", "write", "resource"),
        lease,
        lambda action: "SIDE EFFECT",
    )

    assert result.decision.value == "deny"
    assert "invalidated" in result.reason


def test_concurrent_containment_invalidates_lease_before_execution():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime)
    gateway = ActionGateway(PolicyEngine(), controller)

    lease = gateway.acquire_lease()
    assert lease is not None

    barrier = threading.Barrier(2, timeout=THREAD_TIMEOUT)
    executed = []

    def attacker():
        barrier.wait()
        controller.contain()

    def worker():
        barrier.wait()
        if runtime.lease_valid(lease):
            # Simulate a scheduling gap between validation and the side effect.
            controller.contain()
            if runtime.lease_valid(lease):
                executed.append("SIDE EFFECT")

    t1 = threading.Thread(target=attacker)
    t2 = threading.Thread(target=worker)
    t1.start()
    t2.start()
    t1.join(timeout=THREAD_TIMEOUT)
    t2.join(timeout=THREAD_TIMEOUT)

    assert not t1.is_alive()
    assert not t2.is_alive()
    assert executed == []
    assert runtime.state is RuntimeState.CONTAINED


def test_containment_invalidates_epoch():
    runtime = Runtime("agent-1")
    lease = runtime.acquire_lease()
    assert lease is not None
    original_epoch = runtime.epoch

    runtime.halt()

    assert runtime.epoch == original_epoch + 1
    assert not runtime.lease_valid(lease)


def test_new_lease_cannot_be_acquired_after_halt():
    runtime = Runtime("agent-1")
    runtime.halt()

    assert runtime.acquire_lease() is None


def test_containment_fences_and_runs_external_enforcer_while_callback_is_blocked():
    runtime = Runtime("agent-containment-inflight-boundary")
    lease = runtime.acquire_lease()
    assert lease is not None

    executor_started = threading.Event()
    release_executor = threading.Event()
    enforcer_started = threading.Event()
    containment_completed = threading.Event()
    effects = []

    class RecordingEnforcer:
        name = "recording-enforcer"

        def contain(self, agent_id):
            enforcer_started.set()
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "contained")

        def verify_contained(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "verified")

        def release(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.RELEASED, "released")

        def verify_released(self, agent_id):
            return EnforcementResult(self.name, EnforcementStatus.RELEASED, "verified")

    controller = ContainmentController(runtime, enforcers=[RecordingEnforcer()])

    def blocking_side_effect():
        effects.append("in-flight-started")
        executor_started.set()
        assert release_executor.wait(THREAD_TIMEOUT), "test did not release blocked side effect"
        effects.append("in-flight-completed")
        return "completed"

    worker = threading.Thread(
        target=lambda: runtime.execute_if_active(lease, blocking_side_effect),
        name="blocked-executor",
        daemon=True,
    )
    worker.start()
    assert executor_started.wait(THREAD_TIMEOUT), "side effect did not start"
    assert runtime.inflight_executions == 1

    def contain():
        controller.contain()
        containment_completed.set()

    halter = threading.Thread(target=contain, name="containment-under-test", daemon=True)
    halter.start()

    assert containment_completed.wait(THREAD_TIMEOUT), (
        "containment did not complete while the admitted callback was blocked"
    )
    assert enforcer_started.is_set(), "external enforcement did not start before callback release"
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.acquire_lease() is None
    assert runtime.execute_if_active(lease, lambda: effects.append("stale-side-effect")) is None
    assert effects == ["in-flight-started"]
    assert runtime.inflight_executions == 1

    release_executor.set()
    worker.join(timeout=THREAD_TIMEOUT)
    halter.join(timeout=THREAD_TIMEOUT)

    assert not worker.is_alive(), "executor thread did not finish"
    assert not halter.is_alive(), "containment thread did not finish"
    assert effects == ["in-flight-started", "in-flight-completed"]
    assert runtime.inflight_executions == 0
    assert runtime.state is RuntimeState.CONTAINED


def test_inflight_execution_count_is_released_when_callback_raises():
    runtime = Runtime("agent-callback-exception")
    lease = runtime.acquire_lease()
    assert lease is not None

    def fail():
        raise ValueError("expected test failure")

    with pytest.raises(ValueError, match="expected test failure"):
        runtime.execute_if_active(lease, fail)

    assert runtime.inflight_executions == 0
