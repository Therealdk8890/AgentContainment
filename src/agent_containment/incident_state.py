"""Controller-owned incident state independent of the proof subsystem."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from time import time


class IncidentState(str, Enum):
    OPEN = "open"
    CONTAINED = "contained"
    PROOF_DEGRADED = "proof_degraded"


@dataclass(frozen=True)
class IncidentRecord:
    incident_id: str
    agent_id: str
    state: IncidentState
    containment_epoch: int
    created_at: float
    proof_attached: bool = False
    proof_reference: str | None = None
    reason: str | None = None


class IncidentRegistry:
    """Minimal authoritative incident state owned by AgentContainment.

    Proof is optional metadata. A proof outage can never make containment
    transition back to an executable state or cause evidence to be invented.
    """

    def __init__(self):
        self._records: dict[str, IncidentRecord] = {}

    def record_containment(
        self,
        incident_id: str,
        agent_id: str,
        containment_epoch: int,
        *,
        reason: str | None = None,
    ) -> IncidentRecord:
        if incident_id in self._records:
            raise ValueError(f"incident already exists: {incident_id}")
        record = IncidentRecord(
            incident_id=incident_id,
            agent_id=agent_id,
            state=IncidentState.CONTAINED,
            containment_epoch=containment_epoch,
            created_at=time(),
            reason=reason,
        )
        self._records[incident_id] = record
        return record

    def mark_proof_degraded(self, incident_id: str, *, reason: str) -> IncidentRecord:
        current = self._require(incident_id)
        updated = IncidentRecord(
            incident_id=current.incident_id,
            agent_id=current.agent_id,
            state=IncidentState.PROOF_DEGRADED,
            containment_epoch=current.containment_epoch,
            created_at=current.created_at,
            proof_attached=False,
            proof_reference=None,
            reason=reason,
        )
        self._records[incident_id] = updated
        return updated

    def attach_proof(self, incident_id: str, proof_reference: str) -> IncidentRecord:
        if not proof_reference:
            raise ValueError("proof_reference must be non-empty")
        current = self._require(incident_id)
        updated = IncidentRecord(
            incident_id=current.incident_id,
            agent_id=current.agent_id,
            state=IncidentState.CONTAINED,
            containment_epoch=current.containment_epoch,
            created_at=current.created_at,
            proof_attached=True,
            proof_reference=proof_reference,
            reason=current.reason,
        )
        self._records[incident_id] = updated
        return updated

    def get(self, incident_id: str) -> IncidentRecord | None:
        return self._records.get(incident_id)

    def _require(self, incident_id: str) -> IncidentRecord:
        try:
            return self._records[incident_id]
        except KeyError as exc:
            raise KeyError(f"unknown incident: {incident_id}") from exc
