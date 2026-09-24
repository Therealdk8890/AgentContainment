from dataclasses import dataclass, field
from threading import RLock

from .containment import CapabilitySet, ContainmentController
from .runtime import Runtime


@dataclass
class AgentNode:
    agent_id: str
    parent_id: str | None
    runtime: Runtime
    containment: ContainmentController
    children: set[str] = field(default_factory=set)


class AgentTree:
    """Tracks parent/child relationships with controller-owned spawn/containment serialization."""

    def __init__(self):
        self.nodes: dict[str, AgentNode] = {}
        self._lock = RLock()

    def register_root(
        self,
        agent_id: str,
        capabilities: set[str] | None = None,
    ) -> AgentNode:
        with self._lock:
            if agent_id in self.nodes:
                raise ValueError(f"agent already registered: {agent_id}")
            runtime = Runtime(agent_id)
            controller = ContainmentController(
                runtime,
                CapabilitySet(set(capabilities or set())),
            )
            node = AgentNode(agent_id, None, runtime, controller)
            self.nodes[agent_id] = node
            return node

    def spawn(
        self,
        parent_id: str,
        child_id: str,
        capabilities: set[str] | None = None,
    ) -> AgentNode:
        with self._lock:
            if child_id in self.nodes:
                raise ValueError(f"agent already registered: {child_id}")
            parent = self._require(parent_id)

            if not parent.runtime.can_execute or parent.containment.contained:
                raise RuntimeError(f"parent agent cannot spawn children: {parent_id}")

            inherited = set(parent.containment.capabilities.capabilities)
            if capabilities is not None:
                inherited &= set(capabilities)

            runtime = Runtime(child_id)
            controller = ContainmentController(
                runtime,
                CapabilitySet(inherited),
            )
            node = AgentNode(child_id, parent_id, runtime, controller)
            self.nodes[child_id] = node
            parent.children.add(child_id)
            return node

    def contain(self, agent_id: str) -> list[str]:
        """Contain an agent and every descendant known at the containment fence."""
        with self._lock:
            root = self._require(agent_id)
            contained: list[str] = []
            stack = [root.agent_id]

            while stack:
                current_id = stack.pop()
                current = self._require(current_id)
                current.containment.contain()
                contained.append(current_id)
                stack.extend(sorted(current.children, reverse=True))

            return contained

    def descendants(self, agent_id: str) -> list[str]:
        with self._lock:
            self._require(agent_id)
            result: list[str] = []
            stack = list(self.nodes[agent_id].children)

            while stack:
                child_id = stack.pop()
                result.append(child_id)
                stack.extend(self.nodes[child_id].children)

            return result

    def _require(self, agent_id: str) -> AgentNode:
        try:
            return self.nodes[agent_id]
        except KeyError as exc:
            raise KeyError(f"unknown agent: {agent_id}") from exc
