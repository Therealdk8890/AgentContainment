"""Pluggable enforcement and verification boundaries for AgentContainment."""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Protocol


class EnforcementStatus(str, Enum):
    """Observed state of an external enforcement boundary."""

    ENFORCED = "enforced"
    VERIFICATION_FAILED = "verification_failed"
    DEGRADED = "degraded"
    NOT_CONFIGURED = "not_configured"


@dataclass(frozen=True)
class EnforcementResult:
    """Result returned by an enforcement provider."""

    provider: str
    status: EnforcementStatus
    detail: str = ""

    @property
    def enforced(self) -> bool:
        return self.status is EnforcementStatus.ENFORCED


class Enforcer(Protocol):
    """Controller-owned adapter for an external containment boundary.

    Providers may be backed by Cilium, Tetragon, cgroup v2, eBPF, a cloud
    identity system, or another enforcement mechanism. AgentContainment owns
    the decision; the provider owns the platform-specific mutation.
    """

    name: str

    def contain(self, agent_id: str) -> EnforcementResult:
        """Establish the provider's containment boundary."""

    def release(self, agent_id: str) -> EnforcementResult:
        """Release the provider's containment boundary."""

    def verify_contained(self, agent_id: str) -> EnforcementResult:
        """Verify that containment is actually established."""


class NoopEnforcer:
    """Explicitly configured provider for deployments without OS enforcement."""

    name = "noop"

    def contain(self, agent_id: str) -> EnforcementResult:
        return EnforcementResult(
            self.name,
            EnforcementStatus.NOT_CONFIGURED,
            "no external enforcement provider configured",
        )

    def release(self, agent_id: str) -> EnforcementResult:
        return EnforcementResult(
            self.name,
            EnforcementStatus.NOT_CONFIGURED,
            "no external enforcement provider configured",
        )

    def verify_contained(self, agent_id: str) -> EnforcementResult:
        return EnforcementResult(
            self.name,
            EnforcementStatus.NOT_CONFIGURED,
            "no external enforcement provider configured",
        )
