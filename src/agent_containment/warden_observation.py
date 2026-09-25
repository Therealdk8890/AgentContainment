"""Provider-neutral observation envelope for Warden integration.

This module is deliberately one-way: it converts controller-owned governance
events into observation records. It has no authorization, containment, or
recovery API and must not receive callbacks capable of mutating controller
state.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping

from .governance_event import GovernanceEvent


@dataclass(frozen=True)
class WardenObservation:
    """An immutable, observation-only representation of a governance event."""

    version: int
    observation_id: str
    observed_event_id: str
    observed_event_type: str
    observed_at: float
    agent_id: str
    trace_id: str | None = None
    run_id: str | None = None
    action_id: str | None = None
    policy_decision_id: str | None = None
    incident_id: str | None = None
    containment_epoch: int | None = None
    reason: str | None = None
    attributes: Mapping[str, object] | None = None

    @classmethod
    def from_governance_event(
        cls, event: GovernanceEvent, *, observation_id: str
    ) -> "WardenObservation":
        if not observation_id:
            raise ValueError("observation_id must be non-empty")
        return cls(
            version=1,
            observation_id=observation_id,
            observed_event_id=event.event_id,
            observed_event_type=event.event_type,
            observed_at=event.timestamp,
            agent_id=event.agent_id,
            trace_id=event.trace_id,
            run_id=event.run_id,
            action_id=event.action_id,
            policy_decision_id=event.policy_decision_id,
            incident_id=event.incident_id,
            containment_epoch=event.containment_epoch,
            reason=event.reason,
            attributes=dict(event.attributes or {}),
        )

    def to_dict(self) -> dict[str, object]:
        return {
            "version": self.version,
            "observation_id": self.observation_id,
            "observed_event_id": self.observed_event_id,
            "observed_event_type": self.observed_event_type,
            "observed_at": self.observed_at,
            "agent_id": self.agent_id,
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "action_id": self.action_id,
            "policy_decision_id": self.policy_decision_id,
            "incident_id": self.incident_id,
            "containment_epoch": self.containment_epoch,
            "reason": self.reason,
            "attributes": dict(self.attributes or {}),
            "authority": "observation-only",
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
