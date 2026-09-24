from __future__ import annotations

import os
from pathlib import Path
from typing import Mapping

from .enforcer import EnforcementResult, EnforcementStatus
from .linux_supervisor import LinuxCgroupSupervisor


class CgroupV2Enforcer:
    """Adapt a dedicated cgroup v2 workload boundary to Enforcer."""

    name = "cgroup-v2"

    def __init__(self, cgroup_paths: Mapping[str, str | os.PathLike[str]]):
        self._cgroup_paths = {agent_id: Path(path) for agent_id, path in cgroup_paths.items()}

    def _path(self, agent_id: str) -> Path | None:
        return self._cgroup_paths.get(agent_id)

    def _missing(self, agent_id: str) -> EnforcementResult:
        return EnforcementResult(
            self.name,
            EnforcementStatus.NOT_CONFIGURED,
            f"no cgroup configured for agent {agent_id}",
        )

    def contain(self, agent_id: str) -> EnforcementResult:
        path = self._path(agent_id)
        if path is None:
            return self._missing(agent_id)
        try:
            LinuxCgroupSupervisor.contain(path)
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)
        except Exception as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, f"{type(exc).__name__}: {exc}"
            )

    def verify_contained(self, agent_id: str) -> EnforcementResult:
        path = self._path(agent_id)
        if path is None:
            return self._missing(agent_id)
        try:
            if LinuxCgroupSupervisor.is_populated(path):
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.VERIFICATION_FAILED,
                    f"cgroup remains populated for {agent_id}",
                )
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)
        except Exception as exc:
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                f"{type(exc).__name__}: {exc}",
            )

    def release(self, agent_id: str) -> EnforcementResult:
        path = self._path(agent_id)
        if path is None:
            return self._missing(agent_id)
        try:
            if LinuxCgroupSupervisor.is_populated(path):
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.DEGRADED,
                    f"cgroup remains populated for {agent_id}",
                )
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)
        except Exception as exc:
            return EnforcementResult(
                self.name,
                EnforcementStatus.DEGRADED,
                f"{type(exc).__name__}: {exc}",
            )

    def verify_released(self, agent_id: str) -> EnforcementResult:
        path = self._path(agent_id)
        if path is None:
            return self._missing(agent_id)
        try:
            if LinuxCgroupSupervisor.is_populated(path):
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.VERIFICATION_FAILED,
                    f"cgroup is unexpectedly populated for {agent_id}",
                )
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)
        except Exception as exc:
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                f"{type(exc).__name__}: {exc}",
            )
