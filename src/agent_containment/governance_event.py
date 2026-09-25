"""Stable governance events emitted by the controller for provenance integrations."""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from time import time
from typing import Mapping


@dataclass(frozen=True)
class GovernanceEvent:
    """Controller-owned event envelope suitable for DProvenanceKit ingestion."""
    event_id: str
    event_type: str
    timestamp: float
    agent_id: str
    trace_id: str | None = None
    run_id: str | None = None
    action_id: str | None = None
    policy_decision_id: str | None = None
    incident_id: str | None = None
    containment_epoch: int | None = None
    reason: str | None = None
    attributes: Mapping[str, object] | None = None

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        if self.attributes is None:
            value["attributes"] = {}
        return value

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))

    @classmethod
    def create(
        cls,
        event_id: str,
        event_type: str,
        agent_id: str,
        **kwargs: object,
    ) -> "GovernanceEvent":
        if not event_id or not event_type or not agent_id:
            raise ValueError("event_id, event_type, and agent_id must be non-empty")
        return cls(
            event_id=event_id,
            event_type=event_type,
            timestamp=time(),
            agent_id=agent_id,
            **kwargs,
        )
