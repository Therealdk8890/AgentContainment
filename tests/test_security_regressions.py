"""Regression tests for caller-constructed leases and gateway identity binding."""
from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import ContainmentController
from agent_containment.egress import EgressLease
from agent_containment.runtime import ExecutionLease, Runtime


def make_gateway(agent_id="agent-a"):
    runtime = Runtime(agent_id)
    controller = ContainmentController(runtime)
    return runtime, ActionGateway(PolicyEngine(), controller)


def test_forged_execution_lease_cannot_execute_side_effect():
    runtime, gateway = make_gateway()
    calls = []
    forged = ExecutionLease("agent-a", runtime.epoch)

    result = gateway.execute_with_lease(
        Action("agent-a", "forged", "write", "db"),
        forged,
        lambda action: calls.append(action.operation),
    )

    assert result.decision.value == "deny"
    assert calls == []


def test_runtime_issued_execution_lease_can_execute():
    runtime, gateway = make_gateway()
    lease = gateway.acquire_lease()
    calls = []

    result = gateway.execute_with_lease(
        Action("agent-a", "valid", "read", "db"),
        lease,
        lambda action: calls.append(action.operation) or "ok",
    )

    assert result == "ok"
    assert calls == ["read"]


def test_gateway_rejects_action_agent_id_mismatch():
    runtime, gateway = make_gateway("agent-a")
    lease = gateway.acquire_lease()
    calls = []

    result = gateway.execute_with_lease(
        Action("agent-b", "mismatch", "write", "db"),
        lease,
        lambda action: calls.append(action.operation),
    )

    assert result.decision.value == "deny"
    assert calls == []


def test_forged_egress_lease_cannot_execute_side_effect():
    runtime, gateway = make_gateway()
    calls = []
    forged = EgressLease("agent-a", runtime.epoch)

    result = gateway.execute_egress(
        Action("agent-a", "forged-egress", "http_post", "remote"),
        forged,
        lambda action: calls.append(action.operation),
    )

    assert result.decision.value == "deny"
    assert calls == []



def test_runtime_atomic_gate_rejects_forged_lease_directly():
    runtime = Runtime("agent-a")
    calls = []

    result = runtime.execute_if_active(
        ExecutionLease("agent-a", runtime.epoch),
        lambda: calls.append("executed"),
    )

    assert result is None
    assert calls == []



def test_authorize_rejects_mismatched_agent_without_committing_policy_history():
    runtime, gateway = make_gateway("agent-a")

    result = gateway.authorize(Action("agent-b", "wrong-agent", "read_secret", "db"))

    assert result.decision.value == "deny"
    assert list(gateway.policy.history) == []
