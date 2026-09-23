from agent_containment.agent_tree import AgentTree
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine
from agent_containment.gateway import ActionGateway


tree = AgentTree()
parent = tree.register_root("parent-agent", {"db.read", "network"})
child = tree.spawn("parent-agent", "child-agent")

parent_gateway = ActionGateway(PolicyEngine({"exfiltrate_secret"}), parent.containment)
child_gateway = ActionGateway(PolicyEngine({"exfiltrate_secret"}), child.containment)

print("PARENT:", parent.runtime.state.value)
print("CHILD :", child.runtime.state.value)

attempt = Action(
    "child-agent",
    "child-1",
    "exfiltrate_secret",
    "customer-data",
    risk=100,
)
print("CHILD ATTACK:", child_gateway.authorize(attempt).decision.value)
print("PARENT AFTER CHILD ATTACK:", parent.runtime.state.value)

tree.contain("parent-agent")

post_containment = Action(
    "child-agent",
    "child-2",
    "db.read",
    "customer-data",
)
decision = child_gateway.authorize(post_containment)

print("CONTAINED AGENTS:", tree.contain("parent-agent"))
print("POST-CONTAINMENT CHILD ACTION:", decision.decision.value)
print("CHILD CAPABILITIES:", sorted(child.containment.capabilities.capabilities))
print("PROPAGATION CHECK: PASS" if decision.decision.value == "deny" else "PROPAGATION CHECK: FAIL")
