from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .enforcer import EnforcementResult, EnforcementStatus
from .linux_supervisor import LinuxCgroupSupervisor


@dataclass(frozen=True)
class _CgroupIdentity:
    device: int
    inode: int
    ctime_ns: int


class CgroupV2Enforcer:
    """Adapt a dedicated, identity-bound cgroup v2 workload boundary to Enforcer."""

    name = "cgroup-v2"

    def __init__(self, cgroup_paths: Mapping[str, str | os.PathLike[str]]):
        self._cgroup_paths = {
            agent_id: Path(path) for agent_id, path in cgroup_paths.items()
        }
        self._identities = {
            agent_id: self._identity(path)
            for agent_id, path in self._cgroup_paths.items()
        }

    @staticmethod
    def _identity(path: Path) -> _CgroupIdentity:
        stat = path.stat()
        if not path.is_dir():
            raise ValueError(f"cgroup path is not a directory: {path}")
        return _CgroupIdentity(stat.st_dev, stat.st_ino, stat.st_ctime_ns)

    def _path(self, agent_id: str) -> Path | None:
        return self._cgroup_paths.get(agent_id)

    def _missing(self, agent_id: str) -> EnforcementResult:
        return EnforcementResult(
            self.name,
            EnforcementStatus.NOT_CONFIGURED,
            f"no cgroup configured for agent {agent_id}",
        )

    def _verify_identity(self, agent_id: str, path: Path) -> EnforcementResult | None:
        expected = self._identities[agent_id]
        try:
            actual = self._identity(path)
        except (OSError, ValueError) as exc:
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                f"cgroup identity unavailable: {type(exc).__name__}: {exc}",
            )
        if actual != expected:
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                f"cgroup identity changed for {agent_id}",
            )
        # A directory with the right filesystem identity is not sufficient:
        # require the kernel cgroup v2 control files before trusting its state.
        for control in ("cgroup.events", "cgroup.kill"):
            if not (path / control).is_file():
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.VERIFICATION_FAILED,
                    f"required cgroup control file is missing: {control}",
                )
        return None

    def contain(self, agent_id: str) -> EnforcementResult:
        path = self._path(agent_id)
        if path is None:
            return self._missing(agent_id)
        try:
            identity_failure = self._verify_identity(agent_id, path)
            if identity_failure:
                return identity_failure
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
            identity_failure = self._verify_identity(agent_id, path)
            if identity_failure:
                return identity_failure
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
            identity_failure = self._verify_identity(agent_id, path)
            if identity_failure:
                return identity_failure
            if LinuxCgroupSupervisor.is_populated(path):
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.DEGRADED,
                    f"cgroup remains populated for {agent_id}",
                )
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)
        except Exception as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, f"{type(exc).__name__}: {exc}"
            )

    def verify_released(self, agent_id: str) -> EnforcementResult:
        path = self._path(agent_id)
        if path is None:
            return self._missing(agent_id)
        try:
            identity_failure = self._verify_identity(agent_id, path)
            if identity_failure:
                return identity_failure
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
