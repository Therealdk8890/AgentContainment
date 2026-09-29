from dataclasses import dataclass, field
from threading import RLock


@dataclass(frozen=True)
class CredentialLease:
    credential_id: str
    epoch: int


@dataclass
class CredentialStore:
    """In-memory reference model for revocable, runtime-scoped credentials."""

    credentials: set[str] = field(default_factory=set)
    runtime: object | None = None
    _epochs: dict[str, int] = field(default_factory=dict, init=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def _runtime_epoch_if_active(self) -> int | None:
        if self.runtime is None:
            return None
        # Runtime exposes the authoritative state/epoch boundary. The runtime
        # lock is acquired inside these properties, so issuance cannot observe
        # ACTIVE at one epoch and mint a lease after the runtime has fenced.
        if not self.runtime.can_execute:
            raise RuntimeError("credential issuance requires an active runtime")
        return self.runtime.epoch

    def issue(self, credential_id: str) -> CredentialLease:
        if self.runtime is not None:
            # The runtime state is checked before taking the store lock. Once
            # the runtime is contained, new authority is rejected even if the
            # controller has not yet completed credential cleanup.
            epoch = self._runtime_epoch_if_active()
            assert epoch is not None
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
        if self.runtime is not None and not self.runtime.can_execute:
            return False
        if self.runtime is not None and lease.epoch != self.runtime.epoch:
            return False
        with self._lock:
            return (
                lease.credential_id in self.credentials
                and lease.epoch == self._epochs.get(lease.credential_id, 0)
            )

    def execute_if_valid(self, lease: CredentialLease, executor):
        """Atomically validate a lease and start its modeled side effect."""
        if self.runtime is not None:
            # Runtime execution is the authoritative concurrency boundary:
            # containment cannot race validation and executor invocation.
            from typing import cast

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
            return self.runtime.execute_if_active(
                cast(object, type("_Lease", (), {
                    "agent_id": self.runtime.agent_id,
                    "epoch": lease.epoch,
                })()),
                guarded,
            )

        with self._lock:
            if not (
                lease.credential_id in self.credentials
                and lease.epoch == self._epochs.get(lease.credential_id, 0)
            ):
                return None
            return executor()
