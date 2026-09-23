import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration


def _run(cmd, *, env=None, timeout=10):
    return subprocess.run(cmd, check=True, text=True, capture_output=True, env=env, timeout=timeout)


def _wait_for_file(path: Path, timeout=3):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {path}")


def test_linux_ebpf_blocks_subprocess_egress_after_containment():
    if sys.platform != "linux":
        pytest.skip("Linux cgroup/eBPF integration test")
    if os.geteuid() != 0:
        pytest.skip("requires root for cgroup and BPF operations")
    if os.environ.get("AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS") != "1":
        pytest.skip("set AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1 to run")

    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").exists():
        pytest.skip("cgroup v2 is unavailable")

    controller = Path("build/agent_containment_ebpf_ctl")
    obj = Path("build/agent_containment_egress.bpf.o")
    if not controller.exists() or not obj.exists():
        pytest.skip("build eBPF artifacts first")

    group = root / f"agent-containment-test-{os.getpid()}"
    pin_dir = Path(tempfile.mkdtemp(prefix="agent-containment-bpf-"))
    marker = pin_dir / "connected"
    payload = pin_dir / "payload"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(0.5)
    host, port = server.getsockname()

    child_code = (
        "import socket,sys,time\n"
        "s=socket.create_connection((sys.argv[1],int(sys.argv[2])),timeout=2)\n"
        "s.sendall(b'pre-containment')\n"
        "open(sys.argv[3],'w').write('connected')\n"
        "time.sleep(30)\n"
    )
    child = None
    try:
        group.mkdir()
        child = subprocess.Popen([sys.executable, "-c", child_code, host, str(port), str(marker)])
        (group / "cgroup.procs").write_text(str(child.pid))
        _wait_for_file(marker)

        conn, _ = server.accept()
        assert conn.recv(64) == b"pre-containment"
        conn.close()

        _run([str(controller), "attach", str(obj), str(group), str(pin_dir)])

        probe = subprocess.run(
            [sys.executable, "-c",
             "import socket,sys; s=socket.socket(); s.settimeout(0.5); s.connect((sys.argv[1],int(sys.argv[2])))",
             host, str(port)],
            text=True, capture_output=True, timeout=3,
        )
        assert probe.returncode != 0, probe.stdout + probe.stderr

        with pytest.raises(socket.timeout):
            server.accept()
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        subprocess.run([str(controller), "detach", str(pin_dir)], check=False)
        try:
            if (group / "cgroup.procs").exists():
                pass
            group.rmdir()
        except OSError:
            pass
        server.close()
        for p in (marker, payload):
            p.unlink(missing_ok=True)
        try:
            pin_dir.rmdir()
        except OSError:
            pass