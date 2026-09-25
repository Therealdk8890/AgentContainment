"""Portable incident-to-regression fixtures for governance integrations."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Mapping

from .incident_state import IncidentRecord, IncidentState


@dataclass(frozen=True)
class RegressionFixture:
    """A deterministic failure case that can become a future release gate.

    Evidence references are identifiers only. The fixture does not embed or
    interpret provenance documents, keeping AgentContainment independent of
    any particular proof or claim-verification implementation.
    """

    incident_id: str
    agent_id: str
    agent_version: str | None
    task_context: Mapping[str, Any]
    action_sequence: tuple[str, ...]
    policy_decision: str | None
    evidence_refs: tuple[str, ...]
    containment_result: str
    expected_future_behavior: str

    def __post_init__(self) -> None:
        for name in ("incident_id", "agent_id", "containment_result", "expected_future_behavior"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{name} must be non-empty")
        if self.agent_version is not None and not isinstance(self.agent_version, str):
            raise ValueError("agent_version must be a string or None")
        if not isinstance(self.task_context, Mapping):
            raise ValueError("task_context must be a mapping")
        if any(not isinstance(item, str) or not item for item in self.action_sequence):
            raise ValueError("action_sequence entries must be non-empty strings")
        if self.policy_decision is not None and not isinstance(self.policy_decision, str):
            raise ValueError("policy_decision must be a string or None")
        if any(not isinstance(item, str) or not item for item in self.evidence_refs):
            raise ValueError("evidence_refs entries must be non-empty strings")

    def to_dict(self) -> dict[str, object]:
        return {
            "version": 1,
            "incident_id": self.incident_id,
            "agent_id": self.agent_id,
            "agent_version": self.agent_version,
            "task_context": dict(self.task_context),
            "action_sequence": list(self.action_sequence),
            "policy_decision": self.policy_decision,
            "evidence_refs": list(self.evidence_refs),
            "containment_result": self.containment_result,
            "expected_future_behavior": self.expected_future_behavior,
        }

    def to_wire_dict(self) -> dict[str, object]:
        """Return the portable wire representation consumed by other tools."""
        return {
            "schema": "agent-containment/regression-fixture/v1",
            "fixture": self.to_dict(),
            "fingerprint": self.fingerprint,
        }

    def to_wire_json(self) -> str:
        return json.dumps(
            self.to_wire_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def to_wire_dict(self) -> dict[str, object]:
        """Return the portable wire representation consumed by other tools."""
        return {
            "schema": "agent-containment/regression-fixture/v1",
            "fixture": self.to_dict(),
            "fingerprint": self.fingerprint,
        }

    def to_wire_json(self) -> str:
        return json.dumps(
            self.to_wire_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @property
    def fingerprint(self) -> str:
        """Return a stable SHA-256 identity for this exact regression case."""
        return hashlib.sha256(self.to_json().encode("utf-8")).hexdigest()

    @classmethod
    def from_incident(
        cls,
        incident: IncidentRecord,
        *,
        expected_future_behavior: str,
        agent_version: str | None = None,
        task_context: Mapping[str, Any] | None = None,
        action_sequence: tuple[str, ...] = (),
        policy_decision: str | None = None,
        evidence_refs: tuple[str, ...] = (),
    ) -> "RegressionFixture":
        if incident.state not in (IncidentState.CONTAINED, IncidentState.PROOF_DEGRADED):
            raise ValueError(
                "only contained or proof-degraded incidents can become regression fixtures"
            )
        return cls(
            incident_id=incident.incident_id,
            agent_id=incident.agent_id,
            agent_version=agent_version,
            task_context=task_context or {},
            action_sequence=action_sequence,
            policy_decision=policy_decision,
            evidence_refs=evidence_refs,
            containment_result=incident.state.value,
            expected_future_behavior=expected_future_behavior,
        )
