from __future__ import annotations

import threading

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.runtime import Runtime, RuntimeState


THREAD_TIMEOUT = 3


def test_repeated_containment_race_never_executes_after_fence():
    """Stress the authorization/fence boundary across repeated schedules."""
    for iteration in range(25):
        runtime = Runtime(f"race-agent-{iteration}")
        controller = ContainmentController(runtime)
        gateway = ActionGateway(PolicyEngine(), controller)
        lease = gateway.acquire_lease()
        assert lease is not None

        entered_gate = threading.Event()
        release_gate = threading.Event()
        executed: list[str] = []

        original_execute_if_active = runtime.execute_if_active

        def controlled_execute(candidate, executor):
            entered_gate.set()
            assert release_gate.wait(THREAD_TIMEOUT)
            return original_execute_if_active(candidate, executor)

        runtime.execute_if_active = controlled_execute

        worker = threading.Thread(
            target=lambda: gateway.execute_with_lease(
                Action(
                    runtime.agent_id,
                    f"action-{iteration}",
                    "write",
                    "protected-resource",
                ),
                lease,
                lambda action: executed.append("SIDE_EFFECT"),
            )
        )
        worker.start()

        assert entered_gate.wait(THREAD_TIMEOUT)
        controller.contain()
        release_gate.set()

        worker.join(timeout=THREAD_TIMEOUT)
        assert not worker.is_alive()
        assert executed == []
        assert runtime.state is RuntimeState.CONTAINED
        assert not runtime.lease_valid(lease)
        assert runtime.epoch == 1


def test_concurrent_recovery_and_containment_preserve_fail_closed_final_state():
    """Concurrent recovery/containment must never leave the runtime active."""
    service = ContainmentService()
    runtime = service.register("race-recovery-agent")
    service.contain("race-recovery-agent")
    authorization = service.issue_recovery_authorization("race-recovery-agent")

    barrier = threading.Barrier(2, timeout=THREAD_TIMEOUT)
    results: list[object] = []

    def recover():
        barrier.wait()
        try:
            results.append(service.recover("race-recovery-agent", authorization))
        except Exception as exc:
            results.append(exc)

    def contain():
        barrier.wait()
        try:
            results.append(service.contain("race-recovery-agent"))
        except Exception as exc:
            results.append(exc)

    t1 = threading.Thread(target=recover)
    t2 = threading.Thread(target=contain)
    t1.start()
    t2.start()
    t1.join(timeout=THREAD_TIMEOUT)
    t2.join(timeout=THREAD_TIMEOUT)

    assert not t1.is_alive()
    assert not t2.is_alive()
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch >= 2
    assert len(results) == 2
