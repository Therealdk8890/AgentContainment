from dataclasses import dataclass, field
from threading import RLock

from .runtime import ExecutionLease, Runtime


@dataclass(frozen=True)
class CredentialLease:
    credential_id: str
    epoch: int


@dataclass
class CredentialStore:
    """In-memory reference model for revocable, runtime-scoped credentials."""

    credentials: set[str] = field(default_factory=set)
    runtime: Runtime | None = None
    _epochs: dict[str, int] = field(default_factory=dict, init=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def issue(self, credential_id: str) -> CredentialLease:
        if self.runtime is not None:
            # Runtime.acquire_lease() checks ACTIVE and captures the epoch under
            # one runtime lock, so issuance cannot observe ACTIVE at one epoch
            # and mint authority after the runtime has fenced.
            runtime_lease = self.runtime.acquire_lease()
            if runtime_lease is None:
                raise RuntimeError("credential issuance requires an active runtime")
            epoch = runtime_lease.epoch
            with self._lock:
                self.credentials.add(credential_id)
                self._epochs[credential_id] = epoch
                return CredentialLease(credential_id, epoch)

        with self._lock:
            epoch = self._epochs.get(credential_id, 0)
            self.credentials.add(credential_id)
            return CredentialLease(credential_id, epoch)

    def revoke(self, credential_id: str) -> None:
        with self._lock:
            self.credentials.discard(credential_id)
            self._epochs[credential_id] = self._epochs.get(credential_id, 0) + 1

    def revoke_all(self) -> None:
        with self._lock:
            for credential_id in tuple(self.credentials):
                self._epochs[credential_id] = self._epochs.get(credential_id, 0) + 1
            self.credentials.clear()

    def valid(self, lease: CredentialLease) -> bool:
        if self.runtime is not None:
            runtime_lease = ExecutionLease(self.runtime.agent_id, lease.epoch)
            if not self.runtime.lease_valid(runtime_lease):
                return False
        with self._lock:
            return (
                lease.credential_id in self.credentials
                and lease.epoch == self._epochs.get(lease.credential_id, 0)
            )

    def execute_if_valid(self, lease: CredentialLease, executor):
        """Atomically validate a lease and start its modeled side effect."""
        if self.runtime is not None:
            runtime_lease = ExecutionLease(self.runtime.agent_id, lease.epoch)

            def guarded():
                with self._lock:
                    if not (
                        lease.credential_id in self.credentials
                        and lease.epoch == self._epochs.get(lease.credential_id, 0)
                    ):
                        return None
                    return executor()

            # Runtime.execute_if_active holds its state lock while invoking the
            # guarded callback, so fencing cannot occur between validation and
            # the modeled side effect.
            return self.runtime.execute_if_active(runtime_lease, guarded)

        with self._lock:
            if not (
                lease.credential_id in self.credentials
                and lease.epoch == self._epochs.get(lease.credential_id, 0)
            ):
                return None
            return executor()
