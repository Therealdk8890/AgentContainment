"""Observation-only adapter for Warden.

Warden receives controller-owned governance events and keeps a local
observation stream. It has no reference to authorization, containment,
recovery, or enforcement APIs.
"""
from __future__ import annotations

import secrets
from threading import RLock
from typing import Callable

from .governance_event import GovernanceEvent
from .warden_observation import WardenObservation


class WardenObserver:
    """Controller-event adapter whose only responsibility is observation."""

    def __init__(
        self,
        sink: Callable[[WardenObservation], None] | None = None,
    ) -> None:
        self._sink = sink
        self._observations: list[WardenObservation] = []
        self._lock = RLock()

    def observe(self, event: GovernanceEvent) -> WardenObservation:
        """Record one controller event without returning any control decision."""
        observation = WardenObservation.from_governance_event(
            event,
            observation_id=f"warden:obs:{secrets.token_hex(8)}",
        )
        with self._lock:
            self._observations.append(observation)
        if self._sink is not None:
            self._sink(observation)
        return observation

    def snapshot(self) -> tuple[WardenObservation, ...]:
        """Return the observations Warden has seen, in arrival order."""
        with self._lock:
            return tuple(self._observations)
