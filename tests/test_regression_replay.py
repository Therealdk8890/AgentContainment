from __future__ import annotations

import json
from pathlib import Path

from agent_containment.regression import RegressionFixture
from agent_containment.regression_replay import assert_fixture_replays, replay_fixture


FIXTURE = Path(__file__).parent / "fixtures" / "regression" / "secret-exfiltration.json"


def _load_fixture() -> RegressionFixture:
    data = json.loads(FIXTURE.read_text())
    return RegressionFixture(
        schema=data["schema"],
        fixture_id=data["fixture_id"],
        incident_id=data["incident_id"],
        agent_id=data["agent_id"],
        agent_version=data["agent_version"],
        task=data["task"],
        context=data["context"],
        action_sequence=tuple(data["action_sequence"]),
        policy_decision=data["policy_decision"],
        evidence_refs=tuple(data["evidence_refs"]),
        containment_result=data["containment_result"],
        expected_future_behavior=data["expected_future_behavior"],
    )


def test_incident_fixture_replays_against_current_policy():
    fixture = _load_fixture()
    assert fixture.verify_identity()
    result = replay_fixture(fixture)
    assert result.policy_decision == "halt"
    assert result.containment_required is True


def test_incident_fixture_is_a_release_gate():
    assert_fixture_replays(_load_fixture())
