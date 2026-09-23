"""Egress enforcement primitives for AgentContainment."""
from dataclasses import dataclass
from threading import RLock
from typing import Protocol


@dataclass(frozen=True)
class EgressLease:
    agent_id: str
    epoch: int


class ConnectionTerminator(Protocol):
    def __call__(self) -> None: ...


class EgressController:
    """Fail-closed egress gate and registry for in-flight connections."""

    def __init__(self, runtime):
        self.runtime = runtime
        self._connections: dict[str, dict[str, ConnectionTerminator]] = {}
        self._lock = RLock()

    def acquire_lease(self) -> EgressLease | None:
        if not self.runtime.can_execute:
            return None
        return EgressLease(self.runtime.agent_id, self.runtime.epoch)

    def lease_valid(self, lease: EgressLease) -> bool:
        return (
            lease.agent_id == self.runtime.agent_id
            and lease.epoch == self.runtime.epoch
            and self.runtime.can_execute
        )

    def authorize(self, lease: EgressLease) -> bool:
        return self.lease_valid(lease)

    def register_connection(self, agent_id: str, connection_id: str,
                            terminator: ConnectionTerminator) -> bool:
        with self._lock:
            if agent_id != self.runtime.agent_id or not self.runtime.can_execute:
                return False
            self._connections.setdefault(agent_id, {})[connection_id] = terminator
            return True

    def unregister_connection(self, agent_id: str, connection_id: str) -> None:
        with self._lock:
            connections = self._connections.get(agent_id)
            if connections:
                connections.pop(connection_id, None)
                if not connections:
                    self._connections.pop(agent_id, None)

    def active_connection_ids(self, agent_id: str | None = None) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._connections.get(
                agent_id or self.runtime.agent_id, {}
            ))

    def terminate_all(self, agent_id: str | None = None) -> int:
        target = agent_id or self.runtime.agent_id
        with self._lock:
            terminators = list(self._connections.get(target, {}).values())
            self._connections.pop(target, None)

        terminated = 0
        for terminate in terminators:
            try:
                terminate()
                terminated += 1
            except Exception:
                continue
        return terminated


def hard_close_socket(sock) -> None:
    """Request an abortive TCP close where SO_LINGER is supported."""
    try:
        import socket
        import struct
        sock.setsockopt(
            socket.SOL_SOCKET,
            socket.SO_LINGER,
            struct.pack("ii", 1, 0),
        )
    except (AttributeError, OSError, ImportError):
        pass
    finally:
        sock.close()
