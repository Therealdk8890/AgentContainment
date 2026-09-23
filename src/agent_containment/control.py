"""Controller-owned service facade for AgentContainment.

The service owns containment authority and keeps agent-facing code separate from
the control plane. It is transport-agnostic so a local or remote adapter can
expose it without moving authority into the agent process.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .audit import AuditLog
from .containment import ContainmentController, ContainmentReport
from .models import Action, Decision, DecisionType
from .policy import PolicyEngine
from .runtime import Runtime, RuntimeState


@dataclass
class ManagedAgent:
    runtime: Runtime
    containment: ContainmentController
    metadata: dict[str, str] = field(default_factory=dict)
    policy: PolicyEngine = field(default_factory=PolicyEngine)


class ContainmentService:
    """Controller-owned registry and containment API."""

    def __init__(self, audit: AuditLog | None = None):
        self._agents: dict[str, ManagedAgent] = {}
        self._lock = RLock()
        self.audit = audit

    def register(self, agent_id: str, *, containment: ContainmentController | None = None,
                 metadata: dict[str, str] | None = None,
                 policy: PolicyEngine | None = None) -> Runtime:
        with self._lock:
            if agent_id in self._agents:
                raise ValueError(f"agent already registered: {agent_id}")
            runtime = containment.runtime if containment is not None else Runtime(agent_id)
            if runtime.agent_id != agent_id:
                raise ValueError("containment runtime agent_id does not match registration")
            self._agents[agent_id] = ManagedAgent(
                runtime=runtime,
                containment=containment or ContainmentController(runtime),
                metadata=dict(metadata or {}),
                policy=policy or PolicyEngine(),
            )
            if self.audit:
                self.audit.record("agent_registered", agent_id=agent_id)
            return runtime

    def authorize(self, action: Action) -> Decision:
        managed = self._managed(action.agent_id)
        if not managed.runtime.can_execute:
            decision = Decision(action.action_id, DecisionType.DENY, "agent runtime is not executable")
        else:
            decision = managed.policy.evaluate(action)
            if decision.decision is DecisionType.HALT:
                managed.containment.halt()
        if self.audit:
            self.audit.record(
                "authorization_decision",
                agent_id=action.agent_id,
                action_id=action.action_id,
                decision=decision.decision.value,
                reason=decision.reason,
            )
        return decision

    def unregister(self, agent_id: str) -> None:
        with self._lock:
            self._agents.pop(agent_id, None)

    def status(self, agent_id: str) -> RuntimeState:
        return self._managed(agent_id).runtime.state

    def contain(self, agent_id: str) -> ContainmentReport:
        report = self._managed(agent_id).containment.contain()
        if self.audit:
            self.audit.record(
                "containment",
                agent_id=agent_id,
                decision=DecisionType.CONTAIN.value,
                reason="controller containment requested",
                epoch=report.epoch,
                stages=list(report.stages),
                failures=list(report.failures),
                complete=report.complete,
            )
        return report

    def report(self, agent_id: str) -> ContainmentReport | None:
        return self._managed(agent_id).containment.last_report

    def snapshot(self) -> dict[str, RuntimeState]:
        with self._lock:
            return {agent_id: item.runtime.state for agent_id, item in self._agents.items()}

    def _managed(self, agent_id: str) -> ManagedAgent:
        with self._lock:
            try:
                return self._agents[agent_id]
            except KeyError as exc:
                raise KeyError(f"unknown agent: {agent_id}") from exc
