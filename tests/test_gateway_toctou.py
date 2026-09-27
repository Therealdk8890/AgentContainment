from __future__ import annotations

import threading

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.runtime import Runtime, RuntimeState


THREAD_TIMEOUT = 2


def make_gateway():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime)
    return runtime, controller, ActionGateway(PolicyEngine(), controller)


def test_execution_gateway_closes_lease_check_to_side_effect_race():
    """Containment must not allow a stale lease past the gateway boundary.

    This deliberately pauses the gateway at the atomic execution boundary,
    after authorization has passed but before the side effect can begin. If
    containment can complete there, the stale lease must be rejected.
    """
    runtime, controller, gateway = make_gateway()
    lease = gateway.acquire_lease()
    assert lease is not None

    final_check_passed = threading.Event()
    release_check = threading.Event()
    executed = []

    original_execute_if_active = runtime.execute_if_active

    def controlled_execute_if_active(candidate, executor):
        final_check_passed.set()
        assert release_check.wait(THREAD_TIMEOUT)
        return original_execute_if_active(candidate, executor)

    runtime.execute_if_active = controlled_execute_if_active

    def execute():
        gateway.execute_with_lease(
            Action("agent-1", "a1", "write", "resource"),
            lease,
            lambda action: executed.append("SIDE EFFECT"),
        )

    worker = threading.Thread(target=execute)
    worker.start()

    assert final_check_passed.wait(THREAD_TIMEOUT)
    controller.contain()
    release_check.set()

    worker.join(timeout=THREAD_TIMEOUT)
    assert not worker.is_alive()
    assert runtime.state is RuntimeState.CONTAINED
    assert executed == []


def test_egress_gateway_closes_lease_check_to_side_effect_race():
    """Containment must fence a stale egress lease before network use."""
    runtime, controller, gateway = make_gateway()
    lease = gateway.acquire_egress_lease()
    assert lease is not None

    final_check_passed = threading.Event()
    release_check = threading.Event()
    executed = []

    original_execute_if_active = runtime.execute_if_active

    def controlled_execute_if_active(candidate, executor):
        final_check_passed.set()
        assert release_check.wait(THREAD_TIMEOUT)
        return original_execute_if_active(candidate, executor)

    runtime.execute_if_active = controlled_execute_if_active

    def execute():
        gateway.execute_egress(
            Action("agent-1", "net-1", "POST", "https://example.invalid"),
            lease,
            lambda action: executed.append("NETWORK SIDE EFFECT"),
        )

    worker = threading.Thread(target=execute)
    worker.start()

    assert final_check_passed.wait(THREAD_TIMEOUT)
    controller.contain()
    release_check.set()

    worker.join(timeout=THREAD_TIMEOUT)
    assert not worker.is_alive()
    assert runtime.state is RuntimeState.CONTAINED
    assert executed == []
