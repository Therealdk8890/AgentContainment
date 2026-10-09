import threading

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
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




def test_halt_waits_for_inflight_side_effect_then_rejects_old_lease():
    """Halt cannot interleave with the atomic lease-check-and-start boundary."""
    runtime = Runtime("agent-halt-inflight-boundary")
    lease = runtime.acquire_lease()
    assert lease is not None

    executor_started = threading.Event()
    release_executor = threading.Event()
    halt_lock_attempted = threading.Event()
    halt_completed = threading.Event()
    effects = []

    class ObservedLock:
        """Signal when the halt thread attempts the runtime lock, before blocking."""

        def __init__(self, wrapped):
            self._wrapped = wrapped

        def __enter__(self):
            if threading.current_thread().name == "halt-under-test":
                halt_lock_attempted.set()
            self._wrapped.acquire()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self._wrapped.release()
            return False

    # Instrument the existing lock so the test knows halt has actually reached
    # the lock boundary, rather than relying on a sleep or scheduler timing.
    runtime._lock = ObservedLock(runtime._lock)

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

    halter = threading.Thread(
        target=lambda: (runtime.halt(), halt_completed.set()),
        name="halt-under-test",
        daemon=True,
    )
    halter.start()
    assert halt_lock_attempted.wait(THREAD_TIMEOUT), "halt did not attempt the runtime lock"

    # Halt has reached the lock and must remain blocked while the callback holds it.
    assert not halt_completed.is_set(), "halt completed inside the in-flight execution section"

    release_executor.set()
    worker.join(timeout=THREAD_TIMEOUT)
    halter.join(timeout=THREAD_TIMEOUT)

    assert not worker.is_alive(), "executor thread did not finish"
    assert not halter.is_alive(), "halt thread did not finish"
    assert halt_completed.is_set()
    assert effects == ["in-flight-started", "in-flight-completed"]
    assert runtime.state is RuntimeState.HALTED
    assert runtime.execute_if_active(lease, lambda: effects.append("stale-side-effect")) is None
    assert effects == ["in-flight-started", "in-flight-completed"]
