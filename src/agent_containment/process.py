"""Process containment abstractions."""
from __future__ import annotations
import os
from pathlib import Path
from typing import Protocol

class ProcessContainment(Protocol):
    def contain(self) -> int: ...

class NoopProcessContainment:
    def contain(self) -> int:
        return 0

class LinuxCgroupProcessContainment:
    """Kill all processes in a dedicated cgroup v2."""
    def __init__(self, cgroup_path: str | os.PathLike[str]):
        if os.name != "posix" or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            raise RuntimeError("cgroup v2 is not available on this host")
        self.path = Path(cgroup_path)
        if not self.path.is_dir():
            raise ValueError(f"cgroup path does not exist: {self.path}")

    def contain(self) -> int:
        kill_file = self.path / "cgroup.kill"
        if not kill_file.exists():
            raise RuntimeError("cgroup.kill is unavailable; refusing weaker process-tree kill")
        kill_file.write_text("1")
        return 1
