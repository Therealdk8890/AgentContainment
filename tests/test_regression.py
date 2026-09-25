from agent_containment.incident_state import IncidentRecord, IncidentState
from agent_containment.regression import RegressionFixture


def test_incident_can_be_exported_as_regression_fixture():
    incident = IncidentRecord(
        incident_id="agent-1:containment:7",
        agent_id="agent-1",
        state=IncidentState.CONTAINED,
        containment_epoch=7,
        created_at=1.0,
        reason="unsafe action sequence",
    )

    fixture = RegressionFixture.from_incident(
        incident,
        agent_version="2026.09.24",
        task_context={"task": "document review"},
        action_sequence=("read_source", "export_data", "external_send"),
        policy_decision="contain",
        evidence_refs=("trace:123", "claim:456"),
        expected_future_behavior="deny external_send and contain the runtime",
    )

    assert fixture.to_dict()["version"] == 1
    assert fixture.to_dict()["incident_id"] == incident.incident_id
    assert fixture.to_dict()["containment_result"] == "contained"
    assert fixture.to_json().startswith('{"action_sequence":')


def test_regression_fixture_rejects_empty_expected_behavior():
    incident = IncidentRecord(
        incident_id="incident-1",
        agent_id="agent-1",
        state=IncidentState.CONTAINED,
        containment_epoch=1,
        created_at=1.0,
    )

    try:
        RegressionFixture.from_incident(
            incident,
            expected_future_behavior="",
        )
    except ValueError as exc:
        assert "expected_future_behavior" in str(exc)
    else:
        raise AssertionError("empty regression expectation must fail")
