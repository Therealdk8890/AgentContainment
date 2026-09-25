from __future__ import annotations

import pytest

from agent_containment.regression import (
    RegressionFixtureBuilder,
    assert_regression,
)


def _fixture():
    return RegressionFixtureBuilder().build(
        incident_id="incident-42",
        agent_id="agent-7",
        agent_version="1.4.2",
        task="upload report",
        context={"destination": "external.example", "mode": "autonomous"},
        action_sequence=("read_file", "package_file", "upload_file"),
        policy_decision="HALT",
        evidence_refs=("evidence:abc", "evidence:def"),
        containment_result="certified",
        expected_future_behavior="HALT before upload_file",
    )


def test_fixture_is_deterministic():
    first = _fixture()
    second = _fixture()
    assert first.fixture_id == second.fixture_id
    assert first.digest == second.digest
    assert first.canonical_json() == second.canonical_json()
    assert first.verify_identity()


def test_fixture_is_immutable():
    fixture = _fixture()
    with pytest.raises(AttributeError):
        fixture.policy_decision = "ALLOW"


def test_fixture_canonicalization_is_order_independent():
    a = RegressionFixtureBuilder().build(
        incident_id="incident-1",
        agent_id="agent-1",
        agent_version=None,
        task="task",
        context={"b": 2, "a": 1},
        action_sequence=("one",),
        policy_decision="HALT",
        evidence_refs=("e1",),
        containment_result="certified",
        expected_future_behavior="HALT",
    )
    b = RegressionFixtureBuilder().build(
        incident_id="incident-1",
        agent_id="agent-1",
        agent_version=None,
        task="task",
        context={"a": 1, "b": 2},
        action_sequence=("one",),
        policy_decision="HALT",
        evidence_refs=("e1",),
        containment_result="certified",
        expected_future_behavior="HALT",
    )
    assert a.fixture_id == b.fixture_id


def test_identity_tampering_is_detected():
    fixture = _fixture()
    object.__setattr__(fixture, "policy_decision", "ALLOW")
    assert not fixture.verify_identity()


def test_regression_gate_detects_policy_change():
    with pytest.raises(AssertionError, match="policy decision changed"):
        assert_regression(_fixture(), policy_decision="ALLOW", containment_required=True)


def test_regression_gate_detects_containment_change():
    with pytest.raises(AssertionError, match="containment requirement changed"):
        assert_regression(_fixture(), policy_decision="HALT", containment_required=False)


def test_regression_gate_accepts_same_outcome():
    assert_regression(_fixture(), policy_decision="HALT", containment_required=True)
