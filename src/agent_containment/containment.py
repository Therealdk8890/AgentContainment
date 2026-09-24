from dataclasses import dataclass, field
from .credentials import CredentialStore
from .enforcer import Enforcer, EnforcementStatus
from .runtime import Runtime, RuntimeState


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

    @property
    def complete(self) -> bool:
        return not self.failures

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
        )


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

    def attach_egress(self, egress) -> None:
        self.egress = egress

    def halt(self) -> None:
        self.runtime.halt()

    def contain(self) -> ContainmentReport:
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
                verification = enforcer.verify_contained(self.runtime.agent_id)
                if verification.status is not EnforcementStatus.ENFORCED:
                    failures.append(
                        f"{provider}: containment verification returned "
                        f"{verification.status.value}"
                        + (f": {verification.detail}" if verification.detail else "")
                    )
                else:
                    stages.append(f"enforcer:{provider}:verified")
            except Exception as exc:
                failures.append(f"{provider}: {type(exc).__name__}: {exc}")

        report = ContainmentReport(
            agent_id=self.runtime.agent_id,
            epoch=self.runtime.epoch,
            stages=tuple(stages),
            failures=tuple(failures),
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
