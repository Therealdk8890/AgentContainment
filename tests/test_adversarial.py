from agent_containment import Action, ActionGateway, PolicyEngine
from agent_containment.attack_harness import AttackAttempt, AttackHarness
from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.policy import SequenceRule
from agent_containment.runtime import Runtime, RuntimeState


def make_harness():
    runtime = Runtime("rogue")
    controller = ContainmentController(
        runtime, CapabilitySet({"filesystem.write", "database.write", "network.egress"})
    )
    gateway = ActionGateway(
        PolicyEngine(
            {"exfiltrate_secret", "delete_production"},
            max_risk=90,
            sequence_rules=[
                SequenceRule(
                    "prevent-download-upload-delete",
                    ("download_file", "upload_file", "delete_file"),
                )
            ],
        ),
        controller,
    )
    return runtime, controller, gateway, AttackHarness(gateway, controller)


def test_high_risk_attack_triggers_halt():
    runtime, controller, gateway, harness = make_harness()
    result = harness.attempt(AttackAttempt(
        "secret-exfiltration",
        Action("rogue", "a1", "exfiltrate_secret", "vault/API_KEY", risk=100),
    ))
    assert result.blocked
    assert runtime.state is RuntimeState.HALTED


def test_agent_cannot_continue_after_halt():
    runtime, controller, gateway, harness = make_harness()
    harness.attempt(AttackAttempt(
        "initial-compromise",
        Action("rogue", "a1", "delete_production", "prod-db", risk=100),
    ))
    result = harness.attempt(AttackAttempt(
        "post-halt-write",
        Action("rogue", "a2", "write", "prod-db", risk=1),
    ))
    assert result.blocked
    assert result.decision is not None
    assert runtime.state is RuntimeState.HALTED


def test_dangerous_sequence_triggers_halt():
    runtime, controller, gateway, harness = make_harness()

    first = harness.attempt(AttackAttempt(
        "download",
        Action("rogue", "a1", "download_file", "workspace/report.txt", risk=5),
    ))
    second = harness.attempt(AttackAttempt(
        "upload",
        Action("rogue", "a2", "upload_file", "external/report.txt", risk=10),
    ))
    third = harness.attempt(AttackAttempt(
        "delete",
        Action("rogue", "a3", "delete_file", "workspace/report.txt", risk=10),
    ))

    assert not first.blocked
    assert not second.blocked
    assert third.blocked
    assert third.decision is not None
    assert third.decision.decision.value == "halt"
    assert "prevent-download-upload-delete" in third.reason
    assert runtime.state is RuntimeState.HALTED


def test_containment_revokes_all_capabilities():
    runtime, controller, gateway, harness = make_harness()
    controller.contain()
    assert runtime.state is RuntimeState.CONTAINED
    assert controller.capabilities.capabilities == set()


def test_harness_reports_no_bypass():
    runtime, controller, gateway, harness = make_harness()
    harness.attempt(AttackAttempt(
        "forbidden-operation",
        Action("rogue", "a1", "delete_production", "prod-db", risk=100),
    ))
    harness.attempt(AttackAttempt(
        "after-halt-bypass",
        Action("rogue", "a2", "write", "prod-db", risk=1),
    ))
    harness.assert_contained()
