from dataclasses import dataclass, field
from .runtime import Runtime, RuntimeState


@dataclass
class CapabilitySet:
    capabilities: set[str] = field(default_factory=set)

    def revoke_all(self) -> None:
        self.capabilities.clear()


class ContainmentController:
    def __init__(self, runtime: Runtime, capabilities: CapabilitySet | None = None,
                 process_containment=None, kernel_egress=None):
        self.runtime = runtime
        self.capabilities = capabilities or CapabilitySet()
        self.egress = None
        self.process_containment = process_containment
        self.kernel_egress = kernel_egress

    def attach_egress(self, egress) -> None:
        self.egress = egress

    def halt(self) -> None:
        self.runtime.halt()

    def contain(self) -> None:
        # Fence first: all application leases become stale immediately.
        self.runtime.contain()
        self.capabilities.revoke_all()

        # Enforce the network boundary before killing the runtime.
        if self.kernel_egress is not None:
            self.kernel_egress.contain()

        if self.egress is not None:
            self.egress.terminate_all(self.runtime.agent_id)

        if self.process_containment is not None:
            self.process_containment.contain()

    @property
    def contained(self) -> bool:
        return self.runtime.state is RuntimeState.CONTAINED
