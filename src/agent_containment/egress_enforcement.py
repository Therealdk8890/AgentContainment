"""OS-level egress enforcement adapters."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Protocol


class KernelEgressEnforcer(Protocol):
    def contain(self) -> None: ...


class NoopKernelEgressEnforcer:
    def contain(self) -> None:
        return None


class LinuxCgroupEgressEnforcer:
    """Controller-owned state adapter for a Linux cgroup/eBPF policy.

    This class remains a lightweight reference adapter for deployments that
    bind a controller-owned state file to their own kernel policy.
    """

    def __init__(self, state_path: str):
        self.state_path = Path(state_path)

    def contain(self) -> None:
        self.state_path.write_text("deny\n")


class LinuxEbpfEgressEnforcer:
    """Attach AgentContainment's eBPF egress blocker during containment.

    The privileged controller, not the agent, owns BPF loading, attachment,
    and the pin directory. The supplied cgroup must be dedicated to the
    contained agent and its descendants.
    """

    def __init__(
        self,
        controller_path: str | os.PathLike[str],
        object_path: str | os.PathLike[str],
        cgroup_path: str | os.PathLike[str],
        pin_dir: str | os.PathLike[str],
        *,
        timeout: float = 10.0,
    ):
        self.controller_path = Path(controller_path)
        self.object_path = Path(object_path)
        self.cgroup_path = Path(cgroup_path)
        self.pin_dir = Path(pin_dir)
        self.timeout = timeout

    def contain(self) -> None:
        if os.name != "posix" or not self.cgroup_path.is_dir():
            raise RuntimeError("Linux eBPF containment requires an existing cgroup")
        for path, label in (
            (self.controller_path, "eBPF controller"),
            (self.object_path, "eBPF object"),
        ):
            if not path.is_file():
                raise FileNotFoundError(f"{label} not found: {path}")

        self.pin_dir.mkdir(parents=True, exist_ok=True)
        try:
            subprocess.run(
                [
                    str(self.controller_path),
                    "attach",
                    str(self.object_path),
                    str(self.cgroup_path),
                    str(self.pin_dir),
                ],
                check=True,
                timeout=self.timeout,
                capture_output=True,
                text=True,
            )
        except subprocess.CalledProcessError as exc:
            detail = (exc.stderr or exc.stdout or "").strip()
            raise RuntimeError(
                f"eBPF egress attachment failed"
                + (f": {detail}" if detail else "")
            ) from exc
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError("eBPF egress attachment timed out") from exc
