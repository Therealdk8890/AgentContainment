from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.incident import proof_record
from agent_containment.runtime import Runtime

runtime = Runtime("rogue-agent-01")
controller = ContainmentController(runtime, CapabilitySet({"filesystem.write", "database.write", "network.egress"}))
gateway = ActionGateway(PolicyEngine({"delete_production", "exfiltrate_secret"}, max_risk=90), controller)

actions = [
    Action("rogue-agent-01", "a1", "read", "workspace"),
    Action("rogue-agent-01", "a2", "write", "workspace/report.md", risk=10),
    Action("rogue-agent-01", "a3", "exfiltrate_secret", "vault/API_KEY", risk=100),
    Action("rogue-agent-01", "a4", "delete_production", "prod-db", risk=100),
]

for action in actions:
    decision = gateway.authorize(action)
    print(f"{action.action_id}: {action.operation} -> {decision.decision.value} ({decision.reason})")

record = proof_record("rogue-agent-01", actions, gateway.history, controller.contained)
print("\nIncident evidence:")
print(record)
