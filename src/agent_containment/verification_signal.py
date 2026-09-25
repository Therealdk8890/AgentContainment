"""Inbound, provider-neutral claim verification signals.

ClaimProofKit (or another verifier) may produce a signal, but the controller
retains authority over the resulting policy decision and containment action.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from .models import Action, Decision, DecisionType


@dataclass(frozen=True)
class VerificationSignal:
    """Minimal normalized verification result consumed by policy code."""

    disposition: str
    report_fingerprint: str
    policy_fingerprint: str
    blocking_claim_ids: tuple[str, ...] = ()
    review_claim_ids: tuple[str, ...] = ()
    supported_claim_count: int = 0
    total_claim_count: int = 0
    trace_id: str | None = None
    run_id: str | None = None
    action_id: str | None = None
    version: int = 1

    def __post_init__(self) -> None:
        if self.disposition not in {"allow", "requireReview", "block"}:
            raise ValueError("unsupported verification disposition")
        if not self.report_fingerprint or not self.policy_fingerprint:
            raise ValueError("verification fingerprints must be non-empty")
        if self.supported_claim_count < 0 or self.total_claim_count < 0:
            raise ValueError("claim counts must be non-negative")
        if self.supported_claim_count > self.total_claim_count:
            raise ValueError("supported claim count cannot exceed total claim count")

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "VerificationSignal":
        def strings(key: str) -> tuple[str, ...]:
            raw = value.get(key, ())
            if not isinstance(raw, (list, tuple)):
                raise ValueError(f"{key} must be a list")
            if any(not isinstance(item, str) or not item for item in raw):
                raise ValueError(f"{key} entries must be non-empty strings")
            return tuple(raw)

        return cls(
            version=int(value.get("version", 1)),
            disposition=str(value.get("disposition", "")),
            report_fingerprint=str(value.get("reportFingerprint", "")),
            policy_fingerprint=str(value.get("policyFingerprint", "")),
            blocking_claim_ids=strings("blockingClaimIDs"),
            review_claim_ids=strings("reviewClaimIDs"),
            supported_claim_count=int(value.get("supportedClaimCount", 0)),
            total_claim_count=int(value.get("totalClaimCount", 0)),
            trace_id=value.get("traceID") if isinstance(value.get("traceID"), str) else None,
            run_id=value.get("runID") if isinstance(value.get("runID"), str) else None,
            action_id=value.get("actionID") if isinstance(value.get("actionID"), str) else None,
        )


def decision_from_verification(
    action: Action,
    signal: VerificationSignal,
) -> Decision:
    """Convert a verifier signal into a controller-owned policy decision."""
    if signal.action_id is not None and signal.action_id != action.action_id:
        return Decision(
            action.action_id,
            DecisionType.DENY,
            "verification signal is bound to another action",
        )
    if signal.disposition == "block":
        return Decision(
            action.action_id,
            DecisionType.HENALT if False else DecisionType.HALT,
            "claim verification blocked publication or execution",
        )
    if signal.disposition == "requireReview":
        return Decision(
            action.action_id,
            DecisionType.PAUSE,
            "claim verification requires human review",
        )
    return Decision(action.action_id, DecisionType.ALLOW, "claim verification allows action")
