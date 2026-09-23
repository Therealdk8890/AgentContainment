from dataclasses import dataclass, field
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

    @property
    def complete(self) -> bool:
        return not self.failures


class ContainmentController:
    def __init__(self, runtime: Runtime, capabilities: CapabilitySet | None = None,
                 process_containment=None, kernel_egress=None):
        self.runtime = runtime
        self.capabilities = capabilities or CapabilitySet()
        self.egress = None
        self.process_containment = process_containment
        self.kernel_egress = kernel_egress
        self.last_report: ContainmentReport | None = None

    def attach_egress(self, egress) -> None:
        self.egress = egress

    def halt(self) -> None:
        self.runtime.halt()

    def contain(self) -> ContainmentReport:
        # Fence first. Once this returns, all previously issued application
        # and egress leases are stale even if a later enforcement stage fails.
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
                # Never restore execution after the fence. A partial
                # containment report is safer than silently weakening the
                # boundary because one enforcement adapter failed.
                failures.append(f"{name}: {type(exc).__name__}: {exc}")

        if self.kernel_egress is not None:
            enforce("kernel_egress_contained", self.kernel_egress.contain)

        if self.egress is not None:
            enforce(
                "connections_terminated",
                lambda: self.egress.terminate_all(self.runtime.agent_id),
            )

        if self.process_containment is not None:
            enforce("processes_contained", self.process_containment.contain)

        report = ContainmentReport(
            agent_id=self.runtime.agent_id,
            epoch=self.runtime.epoch,
            stages=tuple(stages),
            failures=tuple(failures),
        )
        self.last_report = report
        return report

    @property
    def contained(self) -> bool:
        return self.runtime.state is RuntimeState.CONTAINED
