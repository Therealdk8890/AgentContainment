from dataclasses import dataclass, field
from threading import RLock


@dataclass(frozen=True)
class CredentialLease:
    credential_id: str
    epoch: int


@dataclass
class CredentialStore:
    """In-memory reference model for revocable credentials."""

    credentials: set[str] = field(default_factory=set)
    _epochs: dict[str, int] = field(default_factory=dict, init=False)
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    def issue(self, credential_id: str) -> CredentialLease:
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
        with self._lock:
            return (
                lease.credential_id in self.credentials
                and lease.epoch == self._epochs.get(lease.credential_id, 0)
            )
