from dataclasses import dataclass, field
from .runtime import Runtime, RuntimeState


@dataclass
class CapabilitySet:
    capabilities: set[str] = field(default_factory=set)

    def revoke_all(self) -> None:
        self.capabilities.clear()


class ContainmentController:
    def __init__(self, runtime: Runtime, capabilities: CapabilitySet | None = None):
        self.runtime = runtime
        self.capabilities = capabilities or CapabilitySet()
        self.egress = None

    def attach_egress(self, egress) -> None:
        self.egress = egress

    def halt(self) -> None:
        self.runtime.halt()

    def contain(self) -> None:
        # Advance the epoch first so outstanding leases become stale before
        # network/process teardown begins.
        self.runtime.contain()
        self.capabilities.revoke_all()
        if self.egress is not None:
            self.egress.terminate_all(self.runtime.agent_id)

    @property
    def contained(self) -> bool:
        return self.runtime.state is RuntimeState.CONTAINED
