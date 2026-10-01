"""Independently derived runtime evidence bound to the runtime epoch.

This module deliberately does not consume GovernanceEvent. It observes Runtime
state directly so provenance consumers can compare two independently derived
facts instead of treating the controller's event as its own proof.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from time import time

from .runtime import Runtime, RuntimeSnapshot


def _canonical(payload: dict[str, object]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")


@dataclass(frozen=True)
class RuntimeObservation:
    schema: str
    runtime_id: str
    agent_id: str
    epoch: int
    state: str
    can_execute: bool
    observed_at: float
    digest: str

    def payload(self) -> dict[str, object]:
        return {
            "schema": self.schema,
            "runtime_id": self.runtime_id,
            "agent_id": self.agent_id,
            "epoch": self.epoch,
            "state": self.state,
            "can_execute": self.can_execute,
            "observed_at": self.observed_at,
        }

    def to_dict(self) -> dict[str, object]:
        return {**self.payload(), "digest": self.digest}

    def verify_integrity(self) -> bool:
        return self.digest == hashlib.sha256(_canonical(self.payload())).hexdigest()


class RuntimeObservationSource:
    """Independent read-only evidence source for controller runtime state."""

    SCHEMA = "agent-containment/runtime-observation/v1"

    def observe(self, runtime: Runtime) -> RuntimeObservation:
        snapshot = runtime.snapshot()
        return self.from_snapshot(snapshot)

    def from_snapshot(
        self,
        snapshot: RuntimeSnapshot,
        *,
        observed_at: float | None = None,
    ) -> RuntimeObservation:
        observation = RuntimeObservation(
            schema=self.SCHEMA,
            runtime_id=snapshot.runtime_id,
            agent_id=snapshot.agent_id,
            epoch=snapshot.epoch,
            state=snapshot.state.value,
            can_execute=snapshot.can_execute,
            observed_at=time() if observed_at is None else observed_at,
            digest="",
        )
        digest = hashlib.sha256(_canonical(observation.payload())).hexdigest()
        return RuntimeObservation(
            schema=observation.schema,
            runtime_id=observation.runtime_id,
            agent_id=observation.agent_id,
            epoch=observation.epoch,
            state=observation.state,
            can_execute=observation.can_execute,
            observed_at=observation.observed_at,
            digest=digest,
        )

    def matches(
        self,
        observation: RuntimeObservation,
        runtime: Runtime,
    ) -> bool:
        """Check that evidence still describes the exact current runtime epoch."""
        if not observation.verify_integrity():
            return False
        current = runtime.snapshot()
        return (
            observation.schema == self.SCHEMA
            and observation.runtime_id == current.runtime_id
            and observation.agent_id == current.agent_id
            and observation.epoch == current.epoch
            and observation.state == current.state.value
            and observation.can_execute == current.can_execute
        )
