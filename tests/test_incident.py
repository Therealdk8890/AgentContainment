from agent_containment import Action, DecisionType
from agent_containment.containment import ContainmentReport
from agent_containment.incident import proof_record


def test_proof_record_binds_containment_report():
    action = Action("agent-1", "a1", "write", "db")
    decision = __import__("agent_containment.models", fromlist=["Decision"]).Decision(
        "a1", DecisionType.DENY, "policy"
    )
    report = ContainmentReport(
        agent_id="agent-1",
        epoch=3,
        stages=("runtime_fenced", "capabilities_revoked", "processes_contained"),
        failures=(),
    )

    record = proof_record("agent-1", [action], [decision], True, containment=report)

    assert record["schema"] == "agent-containment/incident/v1"
    assert record["containment"]["epoch"] == 3
    assert record["containment"]["complete"] is True
    assert record["containment"]["stages"][-1] == "processes_contained"
    assert len(record["containment"]["sha256"]) == 64
