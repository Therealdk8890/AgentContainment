import threading

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.egress import EgressController
from agent_containment.runtime import Runtime, RuntimeState


def make_gateway():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime)
    return runtime, controller, ActionGateway(PolicyEngine(), controller)


def test_egress_lease_invalid_after_containment():
    runtime, controller, gateway = make_gateway()
    lease = gateway.acquire_egress_lease()
    assert lease is not None
    controller.contain()
    assert not gateway.egress.lease_valid(lease)
    assert runtime.state is RuntimeState.CONTAINED


def test_new_egress_lease_cannot_be_acquired_after_containment():
    _, controller, gateway = make_gateway()
    controller.contain()
    assert gateway.acquire_egress_lease() is None


def test_egress_side_effect_is_fenced():
    _, controller, gateway = make_gateway()
    lease = gateway.acquire_egress_lease()
    assert lease is not None
    controller.contain()
    result = gateway.execute_egress(
        Action("agent-1", "net-1", "POST", "https://example.invalid"),
        lease, lambda action: "NETWORK SIDE EFFECT",
    )
    assert result.decision.value == "deny"
    assert "egress lease" in result.reason


def test_inflight_connections_are_terminated_on_containment():
    _, controller, gateway = make_gateway()
    closed = []
    assert gateway.egress.register_connection("agent-1", "conn-1",
                                               lambda: closed.append("conn-1"))
    assert gateway.egress.register_connection("agent-1", "conn-2",
                                               lambda: closed.append("conn-2"))
    controller.contain()
    assert sorted(closed) == ["conn-1", "conn-2"]
    assert gateway.egress.active_connection_ids("agent-1") == ()


def test_failed_terminator_does_not_block_other_connections():
    _, controller, gateway = make_gateway()
    closed = []
    def bad():
        raise RuntimeError("boom")
    assert gateway.egress.register_connection("agent-1", "bad", bad)
    assert gateway.egress.register_connection("agent-1", "good",
                                               lambda: closed.append("good"))
    controller.contain()
    assert closed == ["good"]


def test_connection_cannot_register_after_containment():
    _, controller, gateway = make_gateway()
    controller.contain()
    assert not gateway.egress.register_connection("agent-1", "late", lambda: None)


def test_egress_containment_race_fails_closed():
    runtime, controller, gateway = make_gateway()
    lease = gateway.acquire_egress_lease()
    assert lease is not None
    barrier = threading.Barrier(2)
    executed = []

    def attacker():
        barrier.wait()
        controller.contain()

    def worker():
        barrier.wait()
        if gateway.egress.authorize(lease):
            controller.contain()
            if gateway.egress.authorize(lease):
                executed.append("NETWORK SIDE EFFECT")

    t1 = threading.Thread(target=attacker)
    t2 = threading.Thread(target=worker)
    t1.start(); t2.start()
    t1.join(); t2.join()
    assert executed == []
    assert runtime.state is RuntimeState.CONTAINED


def test_egress_controller_is_shared_with_containment_controller():
    _, controller, gateway = make_gateway()
    assert controller.egress is gateway.egress
    assert isinstance(gateway.egress, EgressController)
