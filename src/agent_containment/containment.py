from dataclasses import dataclass, field
from time import monotonic
import uuid
from .credentials import CredentialStore
from .enforcer import Enforcer, EnforcementStatus
from .runtime import Runtime, RuntimeState
from .proof_receipt import ProofReceipt


@dataclass
class CapabilitySet:
    capabilities: set[str] = field(default_factory=set)

    def revoke_all(self) -> None:
        self.capabilities.clear()


@dataclass(frozen=True)
class ContainmentReport:
    agent_id: str
    epoch: int
    stages: tuple[str, ...]
    failures: tuple[str, ...]
    persistence_failures: tuple[str, ...] = ()
    external_verified: bool = False
    containment_requested_at: float | None = None
    provider_applied_at: float | None = None
    independently_verified_at: float | None = None

    @property
    def enforcement_latency_seconds(self) -> float | None:
        """Elapsed time from containment request to independent verification."""
        if self.containment_requested_at is None or self.independently_verified_at is None:
            return None
        return max(0.0, self.independently_verified_at - self.containment_requested_at)

    @property
    def complete(self) -> bool:
        return not self.failures

    @property
    def certified(self) -> bool:
        """Whether containment has independent external verification evidence."""
        return self.complete and self.external_verified

    @property
    def durable(self) -> bool:
        """Whether the controller successfully persisted the incident fact."""
        return not self.persistence_failures

    def with_persistence_failure(self, failure: str) -> "ContainmentReport":
        if not failure:
            raise ValueError("failure must be non-empty")
        return ContainmentReport(
            agent_id=self.agent_id,
            epoch=self.epoch,
            stages=self.stages,
            failures=self.failures,
            persistence_failures=self.persistence_failures + (failure,),
            external_verified=self.external_verified,
            containment_requested_at=self.containment_requested_at,
            provider_applied_at=self.provider_applied_at,
            independently_verified_at=self.independently_verified_at,
        )
    def to_receipt(
        self,
        secret: bytes,
        *,
        execution_id: str | None = None,
        policy_id: str | None = None,
        receipt_id: str | None = None,
    ) -> ProofReceipt:
        """Create an authenticated receipt from this containment evidence."""
        payload = {
            "schema_version": 1,
            "receipt_id": receipt_id or f"{self.agent_id}:contain:{self.epoch}:{uuid.uuid4()}",
            "execution_id": execution_id,
            "agent_id": self.agent_id,
            "epoch": self.epoch,
            "policy_id": policy_id,
            "stages": list(self.stages),
            "failures": list(self.failures),
            "persistence_failures": list(self.persistence_failures),
            "external_verified": self.external_verified,
            "containment_requested_at": self.containment_requested_at,
            "provider_applied_at": self.provider_applied_at,
            "independently_verified_at": self.independently_verified_at,
            "proof_status": "verified" if self.certified and self.durable else "degraded",
        }
        return ProofReceipt.issue(payload, secret)


@dataclass(frozen=True)
class RecoveryReport:
    """Evidence for a fail-closed recovery transaction."""

    agent_id: str
    contained_epoch: int
    events: tuple[str, ...]
    failures: tuple[str, ...] = ()
    recontainment_failures: tuple[str, ...] = ()
    recovered_epoch: int | None = None

    @property
    def successful(self) -> bool:
        return self.recovered_epoch is not None and not self.failures

    @property
    def proof_status(self) -> str:
        return "verified" if self.successful and not self.recontainment_failures else "degraded"

    def to_receipt(self, secret: bytes, *, execution_id: str | None = None,
                   policy_id: str | None = None, receipt_id: str | None = None) -> ProofReceipt:
        payload = {
            "schema_version": 1,
            "receipt_id": receipt_id or f"{self.agent_id}:recover:{self.contained_epoch}:{uuid.uuid4()}",
            "execution_id": execution_id,
            "agent_id": self.agent_id,
            "contained_epoch": self.contained_epoch,
            "recovered_epoch": self.recovered_epoch,
            "events": list(self.events),
            "failures": list(self.failures),
            "recontainment_failures": list(self.recontainment_failures),
            "recovery_result": "completed" if self.successful else "aborted",
            "proof_status": self.proof_status,
        }
        return ProofReceipt.issue(payload, secret)



class ContainmentController:
    def __init__(self, runtime: Runtime, capabilities: CapabilitySet | None = None,
                 process_containment=None, kernel_egress=None,
                 credentials: CredentialStore | None = None,
                 enforcers: list[Enforcer] | None = None):
        self.runtime = runtime
        self.capabilities = capabilities or CapabilitySet()
        self.credentials = credentials
        self.egress = None
        self.process_containment = process_containment
        self.kernel_egress = kernel_egress
        self.enforcers = list(enforcers or [])
        self.last_report: ContainmentReport | None = None
        self.last_recovery_report: RecoveryReport | None = None

    def attach_egress(self, egress) -> None:
        self.egress = egress

    def halt(self) -> None:
        self.runtime.halt()

    def contain(self) -> ContainmentReport:
        containment_requested_at = monotonic()
        # Fence first. Once this returns, all previously issued application,
        # egress, and credential leases are stale even if later enforcement
        # stages fail.
        self.runtime.contain()
        stages: list[str] = ["runtime_fenced"]
        failures: list[str] = []
        self.capabilities.revoke_all()
        stages.append("capabilities_revoked")

        def enforce(name: str, callback) -> None:
            try:
                callback()
                stages.append(name)
            except Exception as exc:
                # Never restore execution after the fence.
                failures.append(f"{name}: {type(exc).__name__}: {exc}")

        if self.credentials is not None:
            enforce("credentials_revoked", self.credentials.revoke_all)

        if self.kernel_egress is not None:
            enforce("kernel_egress_contained", self.kernel_egress.contain)

        if self.egress is not None:
            enforce(
                "connections_terminated",
                lambda: self.egress.terminate_all(self.runtime.agent_id),
            )

        if self.process_containment is not None:
            enforce("processes_contained", self.process_containment.contain)

        provider_applied_at = None
        verified_enforcers = 0
        for enforcer in self.enforcers:
            provider = getattr(enforcer, "name", type(enforcer).__name__)
            try:
                result = enforcer.contain(self.runtime.agent_id)
                if result.status is not EnforcementStatus.ENFORCED:
                    failures.append(
                        f"{provider}: contain returned {result.status.value}"
                        + (f": {result.detail}" if result.detail else "")
                    )
                    continue
                provider_applied_at = provider_applied_at or monotonic()
                verification = enforcer.verify_contained(self.runtime.agent_id)
                if verification.status is not EnforcementStatus.ENFORCED:
                    failures.append(
                        f"{provider}: containment verification returned "
                        f"{verification.status.value}"
                        + (f": {verification.detail}" if verification.detail else "")
                    )
                else:
                    stages.append(f"enforcer:{provider}:verified")
                    verified_enforcers += 1
            except Exception as exc:
                failures.append(f"{provider}: {type(exc).__name__}: {exc}")

        independently_verified_at = monotonic() if verified_enforcers == len(self.enforcers) and self.enforcers else None
        report = ContainmentReport(
            agent_id=self.runtime.agent_id,
            epoch=self.runtime.epoch,
            stages=tuple(stages),
            failures=tuple(failures),
            external_verified=bool(self.enforcers) and verified_enforcers == len(self.enforcers),
            containment_requested_at=containment_requested_at,
            provider_applied_at=provider_applied_at,
            independently_verified_at=independently_verified_at,
        )
        self.last_report = report
        return report

    def release_enforcers(self) -> tuple[str, ...]:
        """Release and independently verify external enforcement boundaries."""
        failures: list[str] = []
        for enforcer in reversed(self.enforcers):
            provider = getattr(enforcer, "name", type(enforcer).__name__)
            try:
                result = enforcer.release(self.runtime.agent_id)
                if result.status is not EnforcementStatus.RELEASED:
                    failures.append(
                        f"{provider}: release returned {result.status.value}"
                        + (f": {result.detail}" if result.detail else "")
                    )
                    continue
                verification = enforcer.verify_released(self.runtime.agent_id)
                if verification.status is not EnforcementStatus.RELEASED:
                    failures.append(
                        f"{provider}: release verification returned "
                        f"{verification.status.value}"
                        + (f": {verification.detail}" if verification.detail else "")
                    )
            except Exception as exc:
                failures.append(f"{provider}: {type(exc).__name__}: {exc}")
        return tuple(failures)

    def recover(self, capability, expected_epoch: int) -> int:
        """Release external enforcement before allowing runtime recovery.

        Recovery is fail-closed: failed release or runtime recovery triggers
        compensation and leaves the runtime contained. Evidence is retained
        in ``last_recovery_report``.
        """
        contained_epoch = self.runtime.epoch
        events = ["recovery_requested"]
        release_failures = self.release_enforcers()
        if release_failures:
            events.append("external_release_failed")
            recontainment_failures = self.recontain_enforcers()
            events.append("recontainment_verified" if not recontainment_failures else "recontainment_degraded")
            self.last_recovery_report = RecoveryReport(
                agent_id=self.runtime.agent_id,
                contained_epoch=contained_epoch,
                events=tuple(events),
                failures=release_failures,
                recontainment_failures=recontainment_failures,
            )
            raise RuntimeError("recovery aborted; runtime remains contained: " + "; ".join(release_failures))
        events.append("external_release_verified")
        try:
            recovered_epoch = self.runtime.recover(capability, expected_epoch)
        except Exception as exc:
            events.append("runtime_recovery_failed")
            recontainment_failures = self.recontain_enforcers()
            events.append("recontainment_verified" if not recontainment_failures else "recontainment_degraded")
            self.last_recovery_report = RecoveryReport(
                agent_id=self.runtime.agent_id,
                contained_epoch=contained_epoch,
                events=tuple(events),
                failures=(f"{type(exc).__name__}: {exc}",),
                recontainment_failures=recontainment_failures,
            )
            raise
        events.append("runtime_recovery_complete")
        self.last_recovery_report = RecoveryReport(
            agent_id=self.runtime.agent_id,
            contained_epoch=contained_epoch,
            events=tuple(events),
            recovered_epoch=recovered_epoch,
        )
        return recovered_epoch

    def recontain_enforcers(self) -> tuple[str, ...]:
        """Best-effort compensation after a failed recovery transaction."""
        failures: list[str] = []
        for enforcer in self.enforcers:
            provider = getattr(enforcer, "name", type(enforcer).__name__)
            try:
                result = enforcer.contain(self.runtime.agent_id)
                if result.status is not EnforcementStatus.ENFORCED:
                    failures.append(
                        f"{provider}: recontain returned {result.status.value}"
                        + (f": {result.detail}" if result.detail else "")
                    )
                    continue
                verification = enforcer.verify_contained(self.runtime.agent_id)
                if verification.status is not EnforcementStatus.ENFORCED:
                    failures.append(
                        f"{provider}: recontain verification returned "
                        f"{verification.status.value}"
                        + (f": {verification.detail}" if verification.detail else "")
                    )
            except Exception as exc:
                failures.append(f"{provider}: {type(exc).__name__}: {exc}")
        return tuple(failures)

    @property
    def contained(self) -> bool:
        return self.runtime.state is RuntimeState.CONTAINED
