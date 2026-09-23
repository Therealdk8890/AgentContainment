import pytest

from agent_containment.models import Action, DecisionType
from agent_containment.policy import PolicyEngine, SequenceRule


def action(operation: str, action_id: str = "x") -> Action:
    return Action("agent-a", action_id, operation, "/resource")


def test_individual_actions_can_be_allowed():
    policy = PolicyEngine(sequence_rules=[
        SequenceRule("exfil-chain", ("download_file", "upload_file", "delete_file"))
    ])
    assert policy.evaluate(action("download_file", "1")).decision is DecisionType.ALLOW
    assert policy.evaluate(action("upload_file", "2")).decision is DecisionType.ALLOW


def test_collective_sequence_is_halted():
    policy = PolicyEngine(sequence_rules=[
        SequenceRule("exfil-chain", ("download_file", "upload_file", "delete_file"))
    ])
    for op in ("download_file", "upload_file"):
        assert policy.evaluate(action(op)).decision is DecisionType.ALLOW

    decision = policy.evaluate(action("delete_file", "3"))
    assert decision.decision is DecisionType.HALT
    assert "exfil-chain" in decision.reason


def test_denied_action_is_not_committed_to_history():
    policy = PolicyEngine(
        denied_operations={"secret"},
        sequence_rules=[SequenceRule("chain", ("read", "secret", "send"))],
    )
    assert policy.evaluate(action("read")).decision is DecisionType.ALLOW
    assert policy.evaluate(action("secret")).decision is DecisionType.HALT
    assert list(policy.history) == ["read"]


def test_invalid_configuration_rejected():
    with pytest.raises(ValueError):
        PolicyEngine(max_risk=101)
    with pytest.raises(ValueError):
        PolicyEngine(history_limit=0)
    with pytest.raises(ValueError):
        SequenceRule("", ("a",))
    with pytest.raises(ValueError):
        SequenceRule("bad", ())
