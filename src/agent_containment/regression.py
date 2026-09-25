"""Deterministic incident-to-regression fixtures.

Regression fixtures are evidence-derived release inputs. They have no control
authority and cannot authorize, contain, release, or recover an agent.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Mapping, Sequence


def _canonical(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        default=str,
    )


@dataclass(frozen=True)
class RegressionFixture:
    """Immutable description of a previously observed governance failure."""

    schema: str
    fixture_id: str
    incident_id: str
    agent_id: str
    agent_version: str | None
    task: str
    context: Mapping[str, object]
    action_sequence: tuple[str, ...]
    policy_decision: str
    evidence_refs: tuple[str, ...]
    containment_result: str
    expected_future_behavior: str

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["context"] = dict(self.context)
        value["action_sequence"] = list(self.action_sequence)
        value["evidence_refs"] = list(self.evidence_refs)
        return value

    def canonical_json(self) -> str:
        return _canonical(self.to_dict())

    @property
    def digest(self) -> str:
        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()

    def verify_identity(self) -> bool:
        """Verify that fixture_id matches the content-derived identity."""
        return self.fixture_id == self.compute_fixture_id(
            incident_id=self.incident_id,
            agent_id=self.agent_id,
            agent_version=self.agent_version,
            task=self.task,
            context=self.context,
            action_sequence=self.action_sequence,
            policy_decision=self.policy_decision,
            evidence_refs=self.evidence_refs,
            containment_result=self.containment_result,
            expected_future_behavior=self.expected_future_behavior,
        )

    @staticmethod
    def compute_fixture_id(
        *,
        incident_id: str,
        agent_id: str,
        agent_version: str | None,
        task: str,
        context: Mapping[str, object],
        action_sequence: Sequence[str],
        policy_decision: str,
        evidence_refs: Sequence[str],
        containment_result: str,
        expected_future_behavior: str,
    ) -> str:
        payload = {
            "incident_id": incident_id,
            "agent_id": agent_id,
            "agent_version": agent_version,
            "task": task,
            "context": dict(context),
            "action_sequence": list(action_sequence),
            "policy_decision": policy_decision,
            "evidence_refs": list(evidence_refs),
            "containment_result": containment_result,
            "expected_future_behavior": expected_future_behavior,
        }
        return "regression:" + hashlib.sha256(_canonical(payload).encode("utf-8")).hexdigest()[:32]


class RegressionFixtureBuilder:
    """Build fixtures without acquiring any runtime control authority."""

    def build(
        self,
        *,
        incident_id: str,
        agent_id: str,
        agent_version: str | None,
        task: str,
        context: Mapping[str, object],
        action_sequence: Sequence[str],
        policy_decision: str,
        evidence_refs: Sequence[str],
        containment_result: str,
        expected_future_behavior: str,
    ) -> RegressionFixture:
        fixture_id = RegressionFixture.compute_fixture_id(
            incident_id=incident_id,
            agent_id=agent_id,
            agent_version=agent_version,
            task=task,
            context=context,
            action_sequence=action_sequence,
            policy_decision=policy_decision,
            evidence_refs=evidence_refs,
            containment_result=containment_result,
            expected_future_behavior=expected_future_behavior,
        )
        return RegressionFixture(
            schema="agent-containment/regression-fixture/v1",
            fixture_id=fixture_id,
            incident_id=incident_id,
            agent_id=agent_id,
            agent_version=agent_version,
            task=task,
            context=dict(context),
            action_sequence=tuple(action_sequence),
            policy_decision=policy_decision,
            evidence_refs=tuple(evidence_refs),
            containment_result=containment_result,
            expected_future_behavior=expected_future_behavior,
        )


def assert_regression(
    fixture: RegressionFixture,
    *,
    policy_decision: str,
    containment_required: bool,
) -> None:
    """Fail a release test when observed governance behavior changes.

    This function only compares expected control outcomes. It does not invoke
    containment or recovery and therefore cannot become part of the authority
    path.
    """
    if not fixture.verify_identity():
        raise AssertionError("regression fixture identity is invalid")
    if fixture.policy_decision != policy_decision:
        raise AssertionError(
            f"policy decision changed: expected {fixture.policy_decision!r}, got {policy_decision!r}"
        )

    expected_containment = fixture.containment_result not in {
        "not_required",
        "not-configured",
        "none",
    }
    if expected_containment != containment_required:
        raise AssertionError(
            "containment requirement changed: "
            f"expected {expected_containment!r}, got {containment_required!r}"
        )


__all__ = ["RegressionFixture", "RegressionFixtureBuilder", "assert_regression"]
