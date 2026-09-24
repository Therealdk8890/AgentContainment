from dataclasses import dataclass
from enum import Enum
from threading import RLock
from typing import Callable, TypeVar


class RuntimeState(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    HALTED = "halted"
    CONTAINED = "contained"


@dataclass(frozen=True)
class ExecutionLease:
    agent_id: str
    epoch: int


T = TypeVar("T")


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

    def restore_contained(self, epoch: int) -> None:
        """Restore a durably contained runtime without making it executable.

        Recovery is an exact state reconstruction, not a new containment
        event, so the persisted epoch remains authoritative. This is used
        only by the controller while rebuilding runtime state from durable
        incident state.
        """
        if epoch < 0:
            raise ValueError("epoch must be non-negative")
        with self._lock:
            if self.state is RuntimeState.ACTIVE:
                self.state = RuntimeState.CONTAINED
                self._epoch = epoch
                return
            if self.state is RuntimeState.CONTAINED:
                if self._epoch != epoch:
                    raise ValueError(
                        f"contained runtime epoch mismatch: {self._epoch} != {epoch}"
                    )
                return
            raise ValueError(
                f"cannot restore contained state from runtime state {self.state.value}"
            )

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

    def execute_if_active(self, lease: ExecutionLease, executor: Callable[[], T]) -> T | None:
        """Atomically validate a lease and begin the modeled side effect.

        Containment/halt cannot transition the runtime between validation and
        invocation of executor. Once the executor starts, this primitive does
        not claim to interrupt the external side effect; real adapters must
        provide their own cancellation/revocation semantics.
        """
        with self._lock:
            if not (
                lease.agent_id == self.agent_id
                and lease.epoch == self._epoch
                and self.state is RuntimeState.ACTIVE
            ):
                return None
            return executor()

    @property
    def epoch(self) -> int:
        with self._lock:
            return self._epoch

    @property
    def can_execute(self) -> bool:
        with self._lock:
            return self.state is RuntimeState.ACTIVE
