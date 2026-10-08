import pytest

from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.runtime import Runtime, RuntimeState


def test_denied_action_halts_runtime():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime, CapabilitySet({"db.write"}))
    gateway = ActionGateway(PolicyEngine({"delete_production"}), controller)

    result = gateway.authorize(Action("agent-1", "a1", "delete_production", "prod-db", risk=100))

    assert result.decision.value == "halt"
    assert runtime.state is RuntimeState.HALTED


def test_halted_agent_cannot_execute_next_action():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime)
    gateway = ActionGateway(PolicyEngine({"delete_production"}), controller)

    gateway.authorize(Action("agent-1", "a1", "delete_production", "prod-db"))
    result = gateway.authorize(Action("agent-1", "a2", "read", "safe-resource"))

    assert result.decision.value == "deny"


def test_containment_revokes_capabilities():
    runtime = Runtime("agent-1")
    controller = ContainmentController(runtime, CapabilitySet({"shell", "db", "network"}))
    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert controller.capabilities.capabilities == set()
    assert report.complete
    assert report.stages[:2] == ("runtime_fenced", "capabilities_revoked")


def test_containment_stays_fenced_when_kernel_enforcement_fails():
    runtime = Runtime("agent-1")
    calls = []

    class FailingKernel:
        def contain(self):
            calls.append("kernel")
            raise RuntimeError("attach failed")

    class Process:
        def contain(self):
            calls.append("process")
            return 1

    controller = ContainmentController(
        runtime,
        CapabilitySet({"network"}),
        process_containment=Process(),
        kernel_egress=FailingKernel(),
    )

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert not runtime.can_execute
    assert calls == ["kernel", "process"]
    assert not report.complete
    assert report.failures[0].startswith("kernel_egress_contained: RuntimeError:")
    assert "processes_contained" in report.stages


def test_gateway_decision_history_is_bounded():
    runtime = Runtime("agent-history")
    controller = ContainmentController(runtime)
    gateway = ActionGateway(PolicyEngine(), controller, history_limit=3)

    for index in range(10):
        gateway.authorize(Action("agent-history", str(index), "read", "resource"))

    assert len(gateway.history) == 3
    assert [item.action_id for item in gateway.history] == ["7", "8", "9"]


def test_gateway_rejects_nonpositive_history_limit():
    runtime = Runtime("agent-history-invalid")
    controller = ContainmentController(runtime)
    with pytest.raises(ValueError, match="history_limit must be positive or None"):
        ActionGateway(PolicyEngine(), controller, history_limit=0)
