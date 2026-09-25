"""Tamper-evident incident evidence chain.

The chain is downstream proof material. It never participates in authorization,
containment, release, or recovery decisions.

Each node commits to the canonical contents of the prior node, producing a
hash-linked incident timeline. The chain can therefore detect deletion,
mutation, reordering, or insertion after capture.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Mapping, Sequence


SCHEMA = "agent-containment/evidence-chain/v1"
GENESIS = "0" * 64


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True)
class EvidenceNode:
    sequence: int
    event_id: str
    event_type: str
    timestamp: float
    agent_id: str
    incident_id: str | None
    containment_epoch: int | None
    payload: Mapping[str, object]
    previous_hash: str
    node_hash: str

    def to_dict(self) -> dict[str, object]:
        return {
            "schema": SCHEMA,
            "sequence": self.sequence,
            "event_id": self.event_id,
            "event_type": self.event_type,
            "timestamp": self.timestamp,
            "agent_id": self.agent_id,
            "incident_id": self.incident_id,
            "containment_epoch": self.containment_epoch,
            "payload": dict(self.payload),
            "previous_hash": self.previous_hash,
            "node_hash": self.node_hash,
        }


def _node_hash(
    *,
    sequence: int,
    event_id: str,
    event_type: str,
    timestamp: float,
    agent_id: str,
    incident_id: str | None,
    containment_epoch: int | None,
    payload: Mapping[str, object],
    previous_hash: str,
) -> str:
    body = {
        "schema": SCHEMA,
        "sequence": sequence,
        "event_id": event_id,
        "event_type": event_type,
        "timestamp": timestamp,
        "agent_id": agent_id,
        "incident_id": incident_id,
        "containment_epoch": containment_epoch,
        "payload": dict(payload),
        "previous_hash": previous_hash,
    }
    return hashlib.sha256(_canonical(body).encode("utf-8")).hexdigest()


class IncidentEvidenceChain:
    """Append-only, in-memory evidence chain with deterministic verification."""

    def __init__(self) -> None:
        self._nodes: list[EvidenceNode] = []

    @property
    def head_hash(self) -> str:
        return self._nodes[-1].node_hash if self._nodes else GENESIS

    @property
    def nodes(self) -> tuple[EvidenceNode, ...]:
        return tuple(self._nodes)

    def append(
        self,
        *,
        event_id: str,
        event_type: str,
        timestamp: float,
        agent_id: str,
        incident_id: str | None = None,
        containment_epoch: int | None = None,
        payload: Mapping[str, object] | None = None,
    ) -> EvidenceNode:
        if not event_id or not event_type or not agent_id:
            raise ValueError("event_id, event_type, and agent_id must be non-empty")
        if timestamp < 0:
            raise ValueError("timestamp must be non-negative")
        if containment_epoch is not None and containment_epoch < 0:
            raise ValueError("containment_epoch must be non-negative")

        sequence = len(self._nodes)
        previous_hash = self.head_hash
        frozen_payload = json.loads(_canonical(dict(payload or {})))
        node_hash = _node_hash(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            agent_id=agent_id,
            incident_id=incident_id,
            containment_epoch=containment_epoch,
            payload=frozen_payload,
            previous_hash=previous_hash,
        )
        node = EvidenceNode(
            sequence=sequence,
            event_id=event_id,
            event_type=event_type,
            timestamp=timestamp,
            agent_id=agent_id,
            incident_id=incident_id,
            containment_epoch=containment_epoch,
            payload=frozen_payload,
            previous_hash=previous_hash,
            node_hash=node_hash,
        )
        self._nodes.append(node)
        return node

    def verify(self) -> None:
        """Raise ValueError if the chain has been mutated, reordered, or broken."""
        previous = GENESIS
        for expected_sequence, node in enumerate(self._nodes):
            if node.sequence != expected_sequence:
                raise ValueError("evidence sequence is not contiguous")
            if node.previous_hash != previous:
                raise ValueError(f"evidence link broken at sequence {node.sequence}")
            expected_hash = _node_hash(
                sequence=node.sequence,
                event_id=node.event_id,
                event_type=node.event_type,
                timestamp=node.timestamp,
                agent_id=node.agent_id,
                incident_id=node.incident_id,
                containment_epoch=node.containment_epoch,
                payload=node.payload,
                previous_hash=node.previous_hash,
            )
            if node.node_hash != expected_hash:
                raise ValueError(f"evidence node mutated at sequence {node.sequence}")
            previous = node.node_hash

    def snapshot(self) -> tuple[dict[str, object], ...]:
        """Return immutable-by-value evidence suitable for downstream proof storage."""
        self.verify()
        return tuple(json.loads(_canonical(node.to_dict())) for node in self._nodes)

    def digest(self) -> str:
        """Return a deterministic digest of the verified chain."""
        self.verify()
        return hashlib.sha256(_canonical(self.snapshot()).encode("utf-8")).hexdigest()
