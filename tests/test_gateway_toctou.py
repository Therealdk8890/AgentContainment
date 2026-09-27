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

    This deliberately pauses the gateway immediately after its final
    lease_valid() check returns True. If containment can complete before the
    executor starts, the gateway currently has a TOCTOU window.
    """
    runtime, controller, gateway = make_gateway()
    lease = gateway.acquire_lease()
    assert lease is not None

    final_check_passed = threading.Event()
    release_check = threading.Event()
    executed = []

    original_lease_valid = runtime.lease_valid
    calls = 0
    calls_lock = threading.Lock()

    def controlled_lease_valid(candidate):
        nonlocal calls
        result = original_lease_valid(candidate)
        with calls_lock:
            calls += 1
            current_call = calls
        if current_call == 2 and result:
            final_check_passed.set()
            assert release_check.wait(THREAD_TIMEOUT)
        return result

    runtime.lease_valid = controlled_lease_valid

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

    original_authorize = gateway.egress.authorize
    calls = 0
    calls_lock = threading.Lock()

    def controlled_authorize(candidate):
        nonlocal calls
        result = original_authorize(candidate)
        with calls_lock:
            calls += 1
            current_call = calls
        if current_call == 2 and result:
            final_check_passed.set()
            assert release_check.wait(THREAD_TIMEOUT)
        return result

    gateway.egress.authorize = controlled_authorize

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
