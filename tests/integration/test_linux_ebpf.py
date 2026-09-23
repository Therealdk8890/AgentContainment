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
    return subprocess.run(
        cmd, check=True, text=True, capture_output=True, env=env, timeout=timeout
    )


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
    blocked = pin_dir / "blocked"
    escaped = pin_dir / "escaped"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(0.5)
    host, port = server.getsockname()

    child_code = (
        "import os,socket,sys,time\n"
        "group=sys.argv[1]\n"
        "with open(group + '/cgroup.procs','w') as f: f.write(str(os.getpid()))\n"
        "open(sys.argv[4],'w').write('ready')\n"
        "s=socket.create_connection((sys.argv[2],int(sys.argv[3])),timeout=2)\n"
        "s.sendall(b'pre-containment')\n"
        "open(sys.argv[5],'w').write('connected')\n"
        "s.close()\n"
        "if sys.stdin.readline().strip() != 'go': sys.exit(2)\n"
        "try:\n"
        "    s=socket.create_connection((sys.argv[2],int(sys.argv[3])),timeout=1)\n"
        "    s.sendall(b'post-containment')\n"
        "    open(sys.argv[7],'w').write('escaped')\n"
        "    s.close()\n"
        "except OSError:\n"
        "    open(sys.argv[6],'w').write('blocked')\n"
        "time.sleep(1)\n"
    )
    child = None
    try:
        group.mkdir()
        ready = pin_dir / "ready"
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                child_code,
                str(group),
                host,
                str(port),
                str(ready),
                str(marker),
                str(blocked),
                str(escaped),
            ],
            stdin=subprocess.PIPE,
            text=True,
        )

        _wait_for_file(ready)
        _wait_for_file(marker)

        conn, _ = server.accept()
        assert conn.recv(64) == b"pre-containment"
        conn.close()

        _run([str(controller), "attach", str(obj), str(group), str(pin_dir)])

        assert child.stdin is not None
        child.stdin.write("go\n")
        child.stdin.flush()

        _wait_for_file(blocked)
        assert not escaped.exists()

        with pytest.raises(socket.timeout):
            server.accept()

        child.wait(timeout=3)
        assert child.returncode == 0
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        subprocess.run([str(controller), "detach", str(pin_dir)], check=False)
        try:
            group.rmdir()
        except OSError:
            pass
        server.close()
        for p in (marker, blocked, escaped, pin_dir / "ready"):
            p.unlink(missing_ok=True)
        try:
            pin_dir.rmdir()
        except OSError:
            pass
