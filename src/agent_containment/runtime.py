from dataclasses import dataclass
from enum import Enum
from threading import RLock


class RuntimeState(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    HALTED = "halted"
    CONTAINED = "contained"


@dataclass(frozen=True)
class ExecutionLease:
    agent_id: str
    epoch: int


class Runtime:
    """Runtime state with an epoch that invalidates outstanding execution leases."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.state = RuntimeState.ACTIVE
        self._epoch = 0
        self._lock = RLock()

    def halt(self) -> None:
        with self._lock:
            self.state = RuntimeState.HALTED
            self._epoch += 1

    def contain(self) -> None:
        with self._lock:
            self.state = RuntimeState.CONTAINED
            self._epoch += 1

    def acquire_lease(self) -> ExecutionLease | None:
        with self._lock:
            if self.state is not RuntimeState.ACTIVE:
                return None
            return ExecutionLease(self.agent_id, self._epoch)

    def lease_valid(self, lease: ExecutionLease) -> bool:
        with self._lock:
            return (
                lease.agent_id == self.agent_id
                and lease.epoch == self._epoch
                and self.state is RuntimeState.ACTIVE
            )

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def can_execute(self) -> bool:
        with self._lock:
            return self.state is RuntimeState.ACTIVE
