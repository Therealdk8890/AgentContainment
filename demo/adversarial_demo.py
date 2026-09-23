"""Run a safe, deterministic adversarial containment demonstration.

The demo models a rogue action sequence without touching real infrastructure.
It demonstrates individually allowed actions becoming collectively disallowed,
followed by runtime fencing and capability revocation.
"""
from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.attack_harness import AttackAttempt, AttackHarness
from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.policy import SequenceRule
from agent_containment.runtime import Runtime


runtime = Runtime("rogue-demo")
controller = ContainmentController(
    runtime,
    CapabilitySet({"filesystem.write", "database.write", "network.egress"}),
)
policy = PolicyEngine(
    denied_operations={"exfiltrate_secret"},
    max_risk=90,
    sequence_rules=[
        SequenceRule(
            "prevent-download-upload-delete",
            ("download_file", "upload_file", "delete_file"),
        )
    ],
)
gateway = ActionGateway(policy, controller)
harness = AttackHarness(gateway, controller)


attempts = [
    AttackAttempt(
        "download-file",
        Action("rogue-demo", "a1", "download_file", "workspace/report.txt", risk=5),
    ),
    AttackAttempt(
        "upload-file",
        Action("rogue-demo", "a2", "upload_file", "external.example/report.txt", risk=10),
    ),
    AttackAttempt(
        "delete-after-upload",
        Action("rogue-demo", "a3", "delete_file", "workspace/report.txt", risk=10),
    ),
]

print("AGENTCONTAINMENT ADVERSARIAL DEMO")
print("=" * 38)
print("Scenario: individually permitted actions form a forbidden sequence.\n")

for attempt in attempts:
    result = harness.attempt(attempt)
    status = "BLOCKED" if result.blocked else "ALLOWED"
    print(f"[{attempt.action.action_id}] {attempt.action.operation:<20} {status}")
    print(f"    {result.reason}")

    if result.blocked:
        print("\n[!] Dangerous sequence detected")
        print("[!] Initiating containment")
        report = controller.contain()
        print(f"[!] Containment complete: {report.complete}")
        break

print("\n--- CONTAINMENT STATE ---")
print(f"Runtime:       {runtime.state.value.upper()}")
print(f"Epoch:         {runtime.epoch}")
print(f"Capabilities:  {sorted(controller.capabilities.capabilities)}")

# Demonstrate that a post-containment action cannot execute.
bypass = Action("rogue-demo", "bypass", "write", "prod-db", risk=1)
decision = gateway.authorize(bypass)
print(f"Post-containment: {decision.decision.value.upper()} — {decision.reason}")

harness.assert_contained()
print("\nATTACK RESULT: CONTAINED")
