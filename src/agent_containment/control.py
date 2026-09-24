"""Controller-owned service facade for AgentContainment."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from threading import RLock
from typing import Callable

from .audit import AuditLog
from .containment import ContainmentController, ContainmentReport
from .incident_state import IncidentRecord, IncidentRegistry
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
    identity_cgroup: str | None = None


class ContainmentService:
    """Controller-owned registry, identity, containment, and recovery API."""

    def __init__(
        self,
        audit: AuditLog | None = None,
        cgroup_supervisor=None,
        incidents: IncidentRegistry | None = None,
    ):
        self._agents: dict[str, ManagedAgent] = {}
        self._lock = RLock()
        self.audit = audit
        self.cgroup_supervisor = cgroup_supervisor
        self.incidents = incidents or IncidentRegistry()

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

    def configure_containment(self, agent_id: str, containment: ContainmentController) -> None:
        with self._lock:
            managed = self._managed(agent_id)
            if containment.runtime is not managed.runtime:
                raise ValueError("containment runtime must match the registered runtime")
            managed.containment = containment

    def create_workload(self, agent_id: str) -> str:
        if self.cgroup_supervisor is None:
            raise RuntimeError("cgroup supervisor is not configured")
        with self._lock:
            managed = self._managed(agent_id)
            if managed.identity_cgroup is not None:
                raise ValueError(f"agent workload already exists: {agent_id}")
            path = self.cgroup_supervisor.create_agent(agent_id)
            managed.identity_cgroup = str(Path(path).resolve())
            if self.audit:
                self.audit.record(
                    "workload_created", agent_id=agent_id,
                    reason="controller-created cgroup identity boundary",
                    cgroup_path=managed.identity_cgroup,
                )
            return managed.identity_cgroup

    def attach_workload(self, agent_id: str, pid: int) -> str:
        if self.cgroup_supervisor is None:
            raise RuntimeError("cgroup supervisor is not configured")
        if pid <= 0:
            raise ValueError("pid must be positive")
        with self._lock:
            managed = self._managed(agent_id)
            if managed.identity_cgroup is None:
                raise RuntimeError("agent workload has not been created")
            self.cgroup_supervisor.attach_pid(managed.identity_cgroup, pid)
            if self.audit:
                self.audit.record(
                    "workload_attached", agent_id=agent_id,
                    reason="controller attached process to workload cgroup",
                    pid=pid, cgroup_path=managed.identity_cgroup,
                )
            return managed.identity_cgroup

    def identity_cgroup(self, agent_id: str) -> str | None:
        with self._lock:
            return self._managed(agent_id).identity_cgroup

    def issue_identity_token(self, agent_id: str, *, peer_pid: int | None = None) -> str:
        if peer_pid is not None and peer_pid <= 0:
            raise ValueError("peer_pid must be positive")
        with self._lock:
            managed = self._managed(agent_id)
            if managed.identity_cgroup is None:
                raise RuntimeError("create_workload must establish cgroup identity first")
            token = secrets.token_urlsafe(32)
            managed.identity_digest = self._digest_token(token)
            managed.identity_pid = peer_pid
            return token

    def authorize(self, action: Action, *, identity_token: str | None = None,
                  peer_pid: int | None = None,
                  cgroup_membership: Callable[[int, str], bool] | None = None) -> Decision:
        managed = self._managed(action.agent_id)
        authenticated = (
            bool(identity_token)
            and managed.identity_digest is not None
            and self._token_matches(identity_token, managed.identity_digest)
            and (managed.identity_pid is None or peer_pid == managed.identity_pid)
            and managed.identity_cgroup is not None
            and peer_pid is not None
            and cgroup_membership is not None
            and cgroup_membership(peer_pid, managed.identity_cgroup)
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
                "authorization_decision", agent_id=action.agent_id,
                action_id=action.action_id, decision=decision.decision.value,
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
        incident_id = self._incident_id(agent_id, report.epoch)

        # The containment decision is authoritative even when persistence is
        # degraded. Record the fact first; proof/audit is downstream.
        self.incidents.record_containment(
            incident_id,
            agent_id,
            report.epoch,
            reason="controller containment requested",
        )

        if self.audit:
            try:
                self.audit.record(
                    "containment", agent_id=agent_id,
                    decision=DecisionType.CONTAIN.value,
                    reason="controller containment requested",
                    epoch=report.epoch, incident_id=incident_id,
                    stages=list(report.stages), failures=list(report.failures),
                    complete=report.complete,
                )
            except Exception as exc:
                # Never turn a successful runtime fence into an apparent
                # containment failure merely because proof/audit persistence
                # is unavailable. Preserve the known epoch and degrade the
                # incident explicitly instead.
                self.incidents.mark_proof_degraded(
                    incident_id,
                    reason=f"audit persistence unavailable: {type(exc).__name__}: {exc}",
                )
        return report

    def incident(self, agent_id: str) -> IncidentRecord | None:
        """Return the latest persisted incident for an agent, if any."""
        records = [r for r in self.incidents.all() if r.agent_id == agent_id]
        return max(records, key=lambda record: record.created_at, default=None)

    def report(self, agent_id: str) -> ContainmentReport | None:
        return self._managed(agent_id).containment.last_report

    def snapshot(self) -> dict[str, RuntimeState]:
        with self._lock:
            return {agent_id: item.runtime.state for agent_id, item in self._agents.items()}

    @staticmethod
    def _incident_id(agent_id: str, epoch: int) -> str:
        return f"{agent_id}:containment:{epoch}"

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
