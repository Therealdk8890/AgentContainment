"""Controller-owned bootstrap admission checks.

This module is a pre-admission guard for trusted launchers. It is intentionally
not an authorization API: the agent must not be able to choose or bypass the
launcher that invokes it. Production admission should be enforced by the host
service manager or container runtime before the agent workload is started.
"""
from __future__ import annotations

import socket
from pathlib import Path


class BootstrapAdmissionError(RuntimeError):
    """Raised when controller availability cannot be established."""


def require_controller_available(
    socket_path: str | Path, *, timeout: float = 1.0
) -> None:
    """Require a live controller IPC endpoint before admitting a workload."""
    path = Path(socket_path)
    if not path.exists():
        raise BootstrapAdmissionError("controller socket is unavailable")

    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
            client.settimeout(timeout)
            client.connect(str(path))
    except OSError as exc:
        raise BootstrapAdmissionError(
            "controller endpoint is unavailable"
        ) from exc
