"""Linux process supervision for AgentContainment."""
from __future__ import annotations

import os
from pathlib import Path


CGROUP2_ROOT = Path("/sys/fs/cgroup")


class LinuxCgroupSupervisor:
    """Create and manage a dedicated cgroup v2 for one agent workload."""

    def __init__(
        self,
        root: str | os.PathLike[str] = "/sys/fs/cgroup/agent-containment",
    ):
        if os.name != "posix" or not (CGROUP2_ROOT / "cgroup.controllers").exists():
            raise RuntimeError("Linux cgroup v2 is required")
        if str(root) == "auto":
            root = self._delegated_root()
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _delegated_root() -> Path:
        """Return a child root inside the controller's systemd cgroup.

        systemd Delegate=yes grants the non-root controller ownership of its
        service cgroup and permits it to create/manage a subtree beneath it.
        Derive the path from the kernel's process cgroup membership instead of
        hard-coding a slice or unit path.
        """
        status = Path("/proc/self/cgroup")
        if not status.is_file():
            raise RuntimeError("cannot determine controller cgroup")
        for line in status.read_text(encoding="utf-8").splitlines():
            fields = line.split(":", 2)
            if len(fields) == 3 and fields[0] == "0" and fields[2]:
                service_cgroup = (CGROUP2_ROOT / fields[2].lstrip("/")).resolve()
                if service_cgroup == CGROUP2_ROOT or CGROUP2_ROOT not in service_cgroup.parents:
                    raise RuntimeError("controller cgroup is outside cgroup v2 root")
                return service_cgroup / "agents"
        raise RuntimeError("process has no cgroup v2 membership")

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
    def pid_cgroup_path(pid: int) -> str:
        if pid <= 0:
            raise ValueError("pid must be positive")
        status = Path(f"/proc/{pid}/cgroup")
        if not status.is_file():
            raise ProcessLookupError(pid)
        for line in status.read_text().splitlines():
            fields = line.split(":", 2)
            if len(fields) == 3:
                hierarchy, _controllers, path = fields
                if hierarchy == "0" and path:
                    return path
        raise RuntimeError(f"process {pid} has no cgroup v2 membership")

    @classmethod
    def pid_in_cgroup(cls, pid: int, cgroup_path: str | os.PathLike[str]) -> bool:
        """Return whether pid is inside the requested cgroup v2 subtree."""
        requested = Path(cgroup_path).resolve()
        actual = Path("/sys/fs/cgroup", cls.pid_cgroup_path(pid).lstrip("/")).resolve()
        try:
            actual.relative_to(requested)
            return True
        except ValueError:
            return False

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
