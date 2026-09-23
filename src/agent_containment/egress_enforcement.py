"""OS-level egress enforcement adapters."""
from __future__ import annotations
from pathlib import Path
from typing import Protocol

class KernelEgressEnforcer(Protocol):
    def contain(self) -> None: ...

class NoopKernelEgressEnforcer:
    def contain(self) -> None:
        return None

class LinuxCgroupEgressEnforcer:
    """Controller-owned state adapter for a Linux cgroup/eBPF policy."""
    def __init__(self, state_path: str):
        self.state_path = Path(state_path)

    def contain(self) -> None:
        self.state_path.write_text("deny\n")
