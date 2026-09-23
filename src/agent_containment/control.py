"""Controller-owned service facade for AgentContainment."""
from __future__ import annotations

import hashlib
import hmac
import secrets
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
    identity_digest: str | None = None
    identity_pid: int | None = None


class ContainmentService:
    """Controller-owned registry and containment API.

    A Unix transport can bind an agent's bearer capability to the peer PID that
    received it. The PID binding is an additional local-control-plane check;
    OS cgroup identity remains the stronger production boundary.
    """

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

    def issue_identity_token(self, agent_id: str, *, peer_pid: int | None = None) -> str:
        """Issue a fresh bearer capability and optionally bind it to a peer PID."""
        if peer_pid is not None and peer_pid <= 0:
            raise ValueError("peer_pid must be positive")
        with self._lock:
            managed = self._managed(agent_id)
            token = secrets.token_urlsafe(32)
            managed.identity_digest = self._digest_token(token)
            managed.identity_pid = peer_pid
            return token

    def authorize(
        self,
        action: Action,
        *,
        identity_token: str | None = None,
        peer_pid: int | None = None,
    ) -> Decision:
        managed = self._managed(action.agent_id)
        authenticated = (
            managed.identity_digest is None
            or (
                bool(identity_token)
                and self._token_matches(identity_token, managed.identity_digest)
                and (
                    managed.identity_pid is None
                    or peer_pid == managed.identity_pid
                )
            )
        )
        if not authenticated:
            decision = Decision(action.action_id, DecisionType.DENY, "agent identity is not authenticated")
        elif not managed.runtime.can_execute:
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

    @staticmethod
    def _digest_token(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    @staticmethod
    def _token_matches(token: str, digest: str) -> bool:
        return hmac.compare_digest(ContainmentService._digest_token(token), digest)

    def _managed(self, agent_id: str) -> ManagedAgent:
        try:
            return self._agents[agent_id]
        except KeyError as exc:
            raise KeyError(f"unknown agent: {agent_id}") from exc
