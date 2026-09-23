import threading

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.runtime import Runtime, RuntimeState


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

    barrier = threading.Barrier(2)
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
    t1.join()
    t2.join()

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
