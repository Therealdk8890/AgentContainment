"""Stable governance events emitted by the controller.

The event envelope is intentionally small and provider-neutral so downstream
provenance systems can ingest controller lifecycle facts without becoming the
containment authority.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from time import time
from typing import Mapping


EVENT_TYPES = frozenset({
    "agent_registered",
    "authorization_decision",
    "verification_evaluated",
    "containment_requested",
    "capability_revoked",
    "containment_enforced",
    "containment_certified",
    "containment_verification_failed",
    "containment_proof_degraded",
    "recovery_requested",
    "recovery_authorized",
    "recovery_completed",
})


@dataclass(frozen=True)
class GovernanceEvent:
    """Controller-owned event envelope suitable for provenance ingestion."""

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

    def __post_init__(self) -> None:
        for field_name in ("event_id", "event_type", "agent_id"):
            value = getattr(self, field_name)
            if not isinstance(value, str) or not value:
                raise ValueError(f"{field_name} must be non-empty")
        if self.event_type not in EVENT_TYPES:
            raise ValueError(f"unsupported governance event type: {self.event_type}")
        if self.timestamp < 0:
            raise ValueError("timestamp must be non-negative")
        if self.containment_epoch is not None and self.containment_epoch < 0:
            raise ValueError("containment_epoch must be non-negative")
        if self.attributes is not None and not isinstance(self.attributes, Mapping):
            raise ValueError("attributes must be a mapping")

    def to_dict(self) -> dict[str, object]:
        value = asdict(self)
        value["attributes"] = {} if self.attributes is None else dict(self.attributes)
        return value

    def to_json(self) -> str:
        # Canonical serialization is part of the cross-project contract.
        return json.dumps(
            self.to_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    @classmethod
    def create(
        cls,
        event_id: str,
        event_type: str,
        agent_id: str,
        *,
        trace_id: str | None = None,
        run_id: str | None = None,
        action_id: str | None = None,
        policy_decision_id: str | None = None,
        incident_id: str | None = None,
        containment_epoch: int | None = None,
        reason: str | None = None,
        attributes: Mapping[str, object] | None = None,
    ) -> "GovernanceEvent":
        return cls(
            event_id=event_id,
            event_type=event_type,
            timestamp=time(),
            agent_id=agent_id,
            trace_id=trace_id,
            run_id=run_id,
            action_id=action_id,
            policy_decision_id=policy_decision_id,
            incident_id=incident_id,
            containment_epoch=containment_epoch,
            reason=reason,
            attributes=attributes,
        )
