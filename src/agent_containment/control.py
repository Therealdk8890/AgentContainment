"""Controller-owned service facade for AgentContainment.

The service owns containment authority and keeps agent-facing code separate from
the control plane. It is transport-agnostic so a local or remote adapter can
expose it without moving authority into the agent process.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from threading import RLock

from .containment import ContainmentController, ContainmentReport
from .runtime import Runtime, RuntimeState


@dataclass
class ManagedAgent:
    runtime: Runtime
    containment: ContainmentController
    metadata: dict[str, str] = field(default_factory=dict)


class ContainmentService:
    """Controller-owned registry and containment API."""

    def __init__(self):
        self._agents: dict[str, ManagedAgent] = {}
        self._lock = RLock()

    def register(self, agent_id: str, *, containment: ContainmentController | None = None,
                 metadata: dict[str, str] | None = None) -> Runtime:
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
            )
            return runtime

    def unregister(self, agent_id: str) -> None:
        with self._lock:
            self._agents.pop(agent_id, None)

    def status(self, agent_id: str) -> RuntimeState:
        return self._managed(agent_id).runtime.state

    def contain(self, agent_id: str) -> ContainmentReport:
        return self._managed(agent_id).containment.contain()

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
