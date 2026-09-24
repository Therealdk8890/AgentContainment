"""Controller-owned incident state independent of the proof subsystem.

The incident registry is the recovery authority for containment facts. It is
separate from the audit chain so loss of audit/proof persistence cannot cause
the controller to invent a prior containment event.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import asdict, dataclass
from enum import Enum
from pathlib import Path
from threading import RLock
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
    proof_degraded_reason: str | None = None


class IncidentRegistry:
    """Authoritative incident state owned by AgentContainment.

    If *path* is supplied, records are durably persisted with atomic replace.
    Recovery only returns records actually persisted. A missing registry is
    absence of evidence, not an empty historical record.
    """

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self._records: dict[str, IncidentRecord] = {}
        self._lock = RLock()
        self._load()

    @property
    def persistence_available(self) -> bool:
        return self.path is not None

    def record_containment(
        self, incident_id: str, agent_id: str, containment_epoch: int, *,
        reason: str | None = None,
    ) -> IncidentRecord:
        if not incident_id or not agent_id:
            raise ValueError("incident_id and agent_id must be non-empty")
        if containment_epoch < 0:
            raise ValueError("containment_epoch must be non-negative")
        with self._lock:
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
            self._persist_locked()
            return record

    def mark_proof_degraded(self, incident_id: str, *, reason: str) -> IncidentRecord:
        if not reason:
            raise ValueError("reason must be non-empty")
        with self._lock:
            current = self._require(incident_id)
            updated = IncidentRecord(
                incident_id=current.incident_id,
                agent_id=current.agent_id,
                state=IncidentState.PROOF_DEGRADED,
                containment_epoch=current.containment_epoch,
                created_at=current.created_at,
                reason=current.reason,
                proof_degraded_reason=reason,
            )
            self._records[incident_id] = updated
            self._persist_locked()
            return updated

    def attach_proof(self, incident_id: str, proof_reference: str) -> IncidentRecord:
        if not proof_reference:
            raise ValueError("proof_reference must be non-empty")
        with self._lock:
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
                proof_degraded_reason=current.proof_degraded_reason,
            )
            self._records[incident_id] = updated
            self._persist_locked()
            return updated

    def latest_for_agent(self, agent_id: str) -> IncidentRecord | None:
        """Return the latest incident for *agent_id*, if one exists."""
        if not agent_id:
            raise ValueError("agent_id must be non-empty")
        with self._lock:
            records = [r for r in self._records.values() if r.agent_id == agent_id]
            return max(records, key=lambda record: record.created_at, default=None)

    def get(self, incident_id: str) -> IncidentRecord | None:
        with self._lock:
            return self._records.get(incident_id)

    def all(self) -> tuple[IncidentRecord, ...]:
        with self._lock:
            return tuple(self._records.values())

    def _require(self, incident_id: str) -> IncidentRecord:
        try:
            return self._records[incident_id]
        except KeyError as exc:
            raise KeyError(f"unknown incident: {incident_id}") from exc

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            records = raw.get("records")
            if not isinstance(records, list):
                raise ValueError("incident registry records must be a list")
            loaded: dict[str, IncidentRecord] = {}
            for item in records:
                if not isinstance(item, dict):
                    raise ValueError("incident registry record must be an object")
                item = dict(item)
                item["state"] = IncidentState(item["state"])
                record = IncidentRecord(**item)
                if record.incident_id in loaded:
                    raise ValueError(f"duplicate incident: {record.incident_id}")
                loaded[record.incident_id] = record
            self._records = loaded
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid incident registry: {exc}") from exc

    def _persist_locked(self) -> None:
        if self.path is None:
            return
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "records": [
                asdict(record) | {"state": record.state.value}
                for record in self._records.values()
            ],
        }
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
