import ctypes
import errno
import os
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration


def _wait_for_socket(path: Path, timeout: float = 5.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for controller socket: {path}")


def _run_as_nobody(code: str, *args: str, cgroup_path: Path) -> subprocess.CompletedProcess[str]:
    nobody = 65534

    def drop_identity_and_join_cgroup() -> None:
        (cgroup_path / "cgroup.procs").write_text(f"{os.getpid()}\n")
        os.setuid(nobody)

    return subprocess.run(
        [sys.executable, "-c", code, *args],
        capture_output=True,
        text=True,
        preexec_fn=drop_identity_and_join_cgroup,
        check=False,
    )


def test_unprivileged_agent_cannot_interfere_with_controller():
    if sys.platform != "linux":
        pytest.skip("Linux controller isolation integration test")
    if os.geteuid() != 0:
        pytest.skip("requires root to create distinct controller/agent identities")
    if os.environ.get("AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS") != "1":
        pytest.skip("set AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1 to run")

    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").exists():
        pytest.skip("cgroup v2 is unavailable")

    marker = Path(f"/tmp/agent-containment-isolation-{os.getpid()}")
    socket_path = marker / "control.sock"
    controller_cgroup = root / f"agent-containment-controller-{os.getpid()}"
    agent_cgroup = root / f"agent-containment-agent-{os.getpid()}"
    marker.mkdir()
    daemon = None

    try:
        controller_cgroup.mkdir()
        agent_cgroup.mkdir()

        daemon = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "agent_containment.daemon",
                "--socket",
                str(socket_path),
                "--socket-mode",
                "0600",
                "--controller-cgroup",
                str(controller_cgroup),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
        _wait_for_socket(socket_path)

        LinuxCgroupSupervisor = __import__(
            "agent_containment.linux_supervisor",
            fromlist=["LinuxCgroupSupervisor"],
        ).LinuxCgroupSupervisor
        controller_cgroup_actual = LinuxCgroupSupervisor.pid_cgroup_path(daemon.pid)
        controller_membership = LinuxCgroupSupervisor.pid_in_cgroup(
            daemon.pid, controller_cgroup
        )
        assert controller_membership is True, (
            f"controller pid {daemon.pid} reported cgroup {controller_cgroup_actual!r}, "
            f"expected {controller_cgroup!s}"
        )
        assert os.stat(f"/proc/{daemon.pid}").st_uid == 0

        agent_code = r"""
import ctypes
import errno
import os
import signal
import socket
import sys

controller_pid = int(sys.argv[1])
socket_path = sys.argv[2]
agent_cgroup = sys.argv[3]

with open(agent_cgroup + "/cgroup.procs", "w") as f:
    f.write(str(os.getpid()))

results = {}

try:
    os.kill(controller_pid, signal.SIGTERM)
    results["signal_term"] = "unexpectedly_allowed"
except PermissionError:
    results["signal_term"] = "denied"
except ProcessLookupError:
    results["signal_term"] = "controller_gone"

try:
    os.kill(controller_pid, signal.SIGKILL)
    results["signal_kill"] = "unexpectedly_allowed"
except PermissionError:
    results["signal_kill"] = "denied"
except ProcessLookupError:
    results["signal_kill"] = "controller_gone"

libc = ctypes.CDLL(None, use_errno=True)
ptrace = libc.ptrace
ptrace.argtypes = [ctypes.c_uint, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_void_p]
ptrace.restype = ctypes.c_long
rc = ptrace(16, controller_pid, None, None)  # PTRACE_ATTACH
results["ptrace"] = "denied" if rc == -1 and ctypes.get_errno() == errno.EPERM else "unexpectedly_allowed"

try:
    with open(f"/proc/{controller_pid}/mem", "rb") as f:
        f.read(1)
    results["ptrace_state"] = "unexpectedly_allowed"
except (PermissionError, OSError):
    results["ptrace_state"] = "denied"

try:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        s.connect(socket_path)
    results["ipc"] = "unexpectedly_allowed"
except (PermissionError, ConnectionRefusedError, FileNotFoundError, OSError):
    results["ipc"] = "denied"

try:
    os.unlink(socket_path)
    results["socket_tamper"] = "unexpectedly_allowed"
except (PermissionError, OSError):
    results["socket_tamper"] = "denied"

try:
    with open(sys.argv[4] + "/cgroup.procs", "w") as f:
        f.write(str(controller_pid))
    results["cgroup_tamper"] = "unexpectedly_allowed"
except (PermissionError, OSError):
    results["cgroup_tamper"] = "denied"

print(results)
if results != {
    "signal_term": "denied",
    "signal_kill": "denied",
    "ptrace": "denied",
    "ptrace_state": "denied",
    "ipc": "denied",
    "socket_tamper": "denied",
    "cgroup_tamper": "denied",
}:
    raise SystemExit(1)
"""
        # signal is referenced inside the agent snippet; keep the snippet
        # self-contained rather than inheriting test globals.
        
        result = _run_as_nobody(
            agent_code, str(daemon.pid), str(socket_path), str(agent_cgroup), str(controller_cgroup), cgroup_path=agent_cgroup
        )
        assert result.returncode == 0, result.stderr + result.stdout

        # Prove the hostile workload did not kill the controller and that the
        # controller remains responsive after the attack attempts.
        assert daemon.poll() is None

        status = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            status.connect(str(socket_path))
            status.sendall(b'{"command":"snapshot"}\n')
            response = status.recv(4096).decode()
        finally:
            status.close()
        assert '"ok": true' in response
    finally:
        if daemon is not None and daemon.poll() is None:
            daemon.send_signal(signal.SIGTERM)
            try:
                daemon.wait(timeout=3)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=3)
        if daemon is not None and daemon.stderr is not None:
            daemon.stderr.close()
        for path in (agent_cgroup, controller_cgroup):
            try:
                path.rmdir()
            except OSError:
                pass
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
        try:
            marker.rmdir()
        except OSError:
            pass
