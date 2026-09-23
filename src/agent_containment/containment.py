from dataclasses import dataclass, field
from .runtime import Runtime

@dataclass
class CapabilitySet:
    capabilities: set[str] = field(default_factory=set)

    def revoke_all(self) -> None:
        self.capabilities.clear()

class ContainmentController:
    def __init__(self, runtime: Runtime, capabilities: CapabilitySet | None = None):
        self.runtime = runtime
        self.capabilities = capabilities or CapabilitySet()

    def halt(self) -> None:
        self.runtime.halt()

    def contain(self) -> None:
        self.runtime.contain()
        self.capabilities.revoke_all()

    @property
    def contained(self) -> bool:
        return self.runtime.state is RuntimeState.CONTAINED
