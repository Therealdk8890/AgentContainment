from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Mapping, Protocol

from .governance_event import GovernanceEvent


@dataclass(frozen=True)
class ProvenanceRecord:
    schema: str
    event_id: str
    event_type: str
    timestamp: float
    agent_id: str
    trace_id: str | None
    run_id: str | None
    action_id: str | None
    policy_decision_id: str | None
    incident_id: str | None
    containment_epoch: int | None
    reason: str | None
    attributes_json: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "trace_id": self.trace_id,
            "run_id": self.run_id,
            "action_id": self.action_id,
            "policy_decision_id": self.policy_decision_id,
            "incident_id": self.incident_id,
            "containment_epoch": self.containment_epoch,
            "reason": self.reason,
            "attributes": json.loads(self.attributes_json),
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))


class ProvenanceSink(Protocol):
    def append(self, record: ProvenanceRecord) -> None:
        ...


class InMemoryProvenanceSink:
    def __init__(self) -> None:
        self._records: list[ProvenanceRecord] = []

    def append(self, record: ProvenanceRecord) -> None:
        self._records.append(record)

    @property
    def records(self) -> tuple[ProvenanceRecord, ...]:
        return tuple(self._records)


def provenance_record(event: GovernanceEvent) -> ProvenanceRecord:
    attributes: Mapping[str, object] = event.attributes or {}
    attributes_json = json.dumps(dict(attributes), sort_keys=True, separators=(",", ":"), default=str)
    return ProvenanceRecord(
        schema="agent-containment/governance-event/v1",
        event_id=event.event_id,
        event_type=event.event_type,
        timestamp=event.timestamp,
        agent_id=event.agent_id,
        trace_id=event.trace_id,
        run_id=event.run_id,
        action_id=event.action_id,
        policy_decision_id=event.policy_decision_id,
        incident_id=event.incident_id,
        containment_epoch=event.containment_epoch,
        reason=event.reason,
        attributes_json=attributes_json,
    )


class ProvenanceEmitter:
    def __init__(self, sink: ProvenanceSink) -> None:
        self._sink = sink

    def emit(self, event: GovernanceEvent) -> bool:
        record = provenance_record(event)
        try:
            self._sink.append(record)
        except Exception:
            return False
        return True
