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
    controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert controller.capabilities.capabilities == set()
