"""Controller-neutral incident evidence recorder.

This module binds controller events, enforcement results, and Warden
observations into the tamper-evident IncidentEvidenceChain. It is downstream
evidence plumbing and never changes controller state.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from .enforcer import EnforcementResult
from .evidence_chain import IncidentEvidenceChain, EvidenceNode
from .governance_event import GovernanceEvent
from .warden_observation import WardenObservation


def _derived_id(*parts: object) -> str:
    raw = json.dumps(parts, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "evidence:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass(frozen=True)
class IncidentEvidenceRecorder:
    """Append lifecycle evidence without becoming part of control authority."""

    chain: IncidentEvidenceChain

    def record_governance_event(self, event: GovernanceEvent) -> EvidenceNode:
        return self.chain.append(
            event_id=event.event_id,
            event_type=event.event_type,
            timestamp=event.timestamp,
            agent_id=event.agent_id,
            incident_id=event.incident_id,
            containment_epoch=event.containment_epoch,
            payload={
                "source": "agent_containment.controller",
                "trace_id": event.trace_id,
                "run_id": event.run_id,
                "action_id": event.action_id,
                "policy_decision_id": event.policy_decision_id,
                "reason": event.reason,
                "attributes": dict(event.attributes or {}),
            },
        )

    def record_enforcement_result(
        self,
        event: GovernanceEvent,
        result: EnforcementResult,
        *,
        phase: str = "containment",
    ) -> EvidenceNode:
        return self.chain.append(
            event_id=_derived_id(
                event.event_id,
                "enforcement",
                result.provider,
                result.status.value,
                result.detail,
                phase,
            ),
            event_type=f"enforcement.{phase}.{result.status.value}",
            timestamp=event.timestamp,
            agent_id=event.agent_id,
            incident_id=event.incident_id,
            containment_epoch=event.containment_epoch,
            payload={
                "source": "enforcement_provider",
                "provider": result.provider,
                "status": result.status.value,
                "enforced": result.enforced,
                "released": result.released,
                "detail": result.detail,
                "controller_event_id": event.event_id,
            },
        )

    def record_warden_observation(
        self, observation: WardenObservation
    ) -> EvidenceNode:
        return self.chain.append(
            event_id=observation.observation_id,
            event_type=f"warden.{observation.observed_event_type}",
            timestamp=observation.observed_at,
            agent_id=observation.agent_id,
            incident_id=observation.incident_id,
            containment_epoch=observation.containment_epoch,
            payload={
                "source": "warden.observation",
                "observed_event_id": observation.observed_event_id,
                "observed_event_type": observation.observed_event_type,
                "trace_id": observation.trace_id,
                "run_id": observation.run_id,
                "action_id": observation.action_id,
                "policy_decision_id": observation.policy_decision_id,
                "reason": observation.reason,
                "attributes": dict(observation.attributes or {}),
                "authority": "observation-only",
            },
        )

    def verify(self) -> None:
        self.chain.verify()

    @property
    def digest(self) -> str:
        return self.chain.digest()
