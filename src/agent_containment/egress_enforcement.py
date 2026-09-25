"""OS-level egress enforcement adapters."""
from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import Protocol

from .enforcer import EnforcementResult, EnforcementStatus


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


class LinuxEbpfEgressEnforcer:
    """Low-level kernel egress adapter used by the provider-neutral boundary."""

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

    def _run(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(self.controller_path), *args],
            check=False,
            timeout=self.timeout,
            capture_output=True,
            text=True,
        )

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
            result = self._run(
                "attach",
                str(self.object_path),
                str(self.cgroup_path),
                str(self.pin_dir),
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise RuntimeError(f"eBPF egress attachment failed: {exc}") from exc
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            raise RuntimeError(
                "eBPF egress attachment failed"
                + (f": {detail}" if detail else "")
            )


class LinuxEbpfExternalEnforcer:
    """Provider-neutral external-enforcement adapter for Linux eBPF.

    Containment is certified only after the controller can independently
    reopen the pinned kernel BPF link. Real-host integration tests additionally
    observe the protected workload's network behavior.
    """

    name = "linux-ebpf-egress"

    def __init__(
        self,
        controller_path: str | os.PathLike[str],
        object_path: str | os.PathLike[str],
        cgroup_path: str | os.PathLike[str],
        pin_dir: str | os.PathLike[str],
        *,
        timeout: float = 10.0,
    ):
        self._kernel = LinuxEbpfEgressEnforcer(
            controller_path, object_path, cgroup_path, pin_dir, timeout=timeout
        )
        self._controller = Path(controller_path)
        self._pin_dir = Path(pin_dir)
        self._timeout = timeout

    def contain(self, agent_id: str) -> EnforcementResult:
        try:
            self._kernel.contain()
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, str(exc)
            )

    def verify_contained(self, agent_id: str) -> EnforcementResult:
        try:
            result = subprocess.run(
                [str(self._controller), "verify", str(self._pin_dir)],
                check=False,
                timeout=self._timeout,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.VERIFICATION_FAILED, str(exc)
            )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                detail or "pinned eBPF link could not be reopened",
            )
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def release(self, agent_id: str) -> EnforcementResult:
        try:
            result = subprocess.run(
                [str(self._controller), "detach", str(self._pin_dir)],
                check=False,
                timeout=self._timeout,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            return EnforcementResult(self.name, EnforcementStatus.DEGRADED, str(exc))
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED,
                detail or "eBPF detach failed",
            )
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)

    def verify_released(self, agent_id: str) -> EnforcementResult:
        link = self._pin_dir / "egress_link"
        if link.exists():
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                "pinned eBPF link remains present",
            )
        return EnforcementResult(self.name, EnforcementStatus.RELEASED)
