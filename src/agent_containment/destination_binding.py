"""Provider-owned destination egress binding boundary.

This module defines the runtime context a destination-binding provider must
receive before it can translate policy destinations into enforcement state.
It does not perform DNS resolution or kernel/network mutation.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from .destination_egress import Destination


@dataclass(frozen=True)
class DestinationBindingContext:
    """Authority context that scopes one destination binding."""

    policy_id: str
    policy_digest: str
    agent_id: str
    runtime_id: str
    epoch: int
    destinations: tuple[Destination, ...]

    def __post_init__(self) -> None:
        if self.epoch < 0:
            raise ValueError("destination binding epoch must be non-negative")


@dataclass(frozen=True)
class DestinationBindingEvidence:
    """Provider evidence returned for a successfully bound destination set."""

    provider: str
    provider_version: str
    effective_config_digest: str
    verification_method: str
    verified: bool


class DestinationBindingProvider(Protocol):
    """Controller-owned provider boundary for destination allowlisting.

    Implementations own destination translation, installation, and live-state
    verification. A provider must not claim enforcement from API acceptance
    alone; verified must reflect independent verification of effective state.
    """

    name: str
    version: str
    capabilities: frozenset[str]

    def bind_destinations(
        self,
        context: DestinationBindingContext,
    ) -> DestinationBindingEvidence:
        """Install and independently verify the context destinations."""
        ...