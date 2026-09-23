"""Linux process supervision for AgentContainment.

This module owns a dedicated cgroup v2 for an agent workload. Privileged host
configuration remains a deployment concern.
"""
from __future__ import annotations

import os
from pathlib import Path


class LinuxCgroupSupervisor:
    """Create and manage a dedicated cgroup v2 for one agent."""

    def __init__(self, root: str | os.PathLike[str] = "/sys/fs/cgroup/agent-containment"):
        if os.name != "posix" or not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            raise RuntimeError("Linux cgroup v2 is required")
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    def create_agent(self, agent_id: str) -> Path:
        path = self.root / self._safe_name(agent_id)
        path.mkdir(exist_ok=False)
        return path

    @staticmethod
    def _safe_name(agent_id: str) -> str:
        if not isinstance(agent_id, str) or not agent_id or agent_id in {".", ".."}:
            raise ValueError("agent_id must be a non-empty string")
        if "/" in agent_id or "\\" in agent_id or "\x00" in agent_id:
            raise ValueError("agent_id may not contain path separators or NUL")
        return agent_id

    @staticmethod
    def attach_pid(cgroup_path: str | os.PathLike[str], pid: int) -> None:
        if pid <= 0:
            raise ValueError("pid must be positive")
        path = Path(cgroup_path)
        if not path.is_dir():
            raise ValueError(f"cgroup path does not exist: {path}")
        (path / "cgroup.procs").write_text(f"{pid}\n")

    @staticmethod
    def is_populated(cgroup_path: str | os.PathLike[str]) -> bool:
        events = Path(cgroup_path) / "cgroup.events"
        if not events.is_file():
            return False
        values = {}
        for line in events.read_text().splitlines():
            key, _, value = line.partition(" ")
            if key:
                values[key] = value.strip()
        return values.get("populated") == "1"

    @staticmethod
    def contain(cgroup_path: str | os.PathLike[str]) -> int:
        kill_file = Path(cgroup_path) / "cgroup.kill"
        if not kill_file.is_file():
            raise RuntimeError("cgroup.kill is unavailable")
        kill_file.write_text("1\n")
        return 1

    @staticmethod
    def remove(cgroup_path: str | os.PathLike[str]) -> None:
        Path(cgroup_path).rmdir()
