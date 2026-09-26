import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from agent_containment.audit import AuditLog
from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.egress_enforcement import LinuxEbpfExternalEnforcer
from agent_containment.process import LinuxCgroupProcessContainment
from agent_containment.proof import record_proof
from agent_containment.runtime import Runtime, RuntimeState
from agent_containment.warden_observer import WardenObserver


pytestmark = pytest.mark.integration


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
    bpffs = Path("/sys/fs/bpf")
    if not bpffs.is_dir():
        pytest.skip("BPF filesystem is unavailable")
    pin_dir = bpffs / f"agent-containment-test-{os.getpid()}"
    marker_dir = Path(tempfile.mkdtemp(prefix="agent-containment-test-"))
    audit_path = marker_dir / "audit.jsonl"
    marker = marker_dir / "connected"
    blocked = marker_dir / "blocked"
    escaped = marker_dir / "escaped"
    attempted = marker_dir / "attempted"

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
        "    open(sys.argv[8],'w').write('attempted')\n"
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
        ready = marker_dir / "ready"
        child = subprocess.Popen(
            [
                sys.executable, "-c", child_code, str(group), host, str(port),
                str(ready), str(marker), str(blocked), str(escaped), str(attempted),
            ],
            stdin=subprocess.PIPE,
            text=True,
        )

        _wait_for_file(ready)
        _wait_for_file(marker)

        conn, _ = server.accept()
        assert conn.recv(64) == b"pre-containment"
        conn.close()

        runtime = Runtime("adversarial-agent")
        lease = runtime.acquire_lease()
        assert lease is not None

        audit = AuditLog(audit_path)
        enforcer = LinuxEbpfExternalEnforcer(
            str(controller), str(obj), str(group), str(pin_dir)
        )
        containment = ContainmentController(
            runtime,
            enforcers=[enforcer],
        )
        observer = WardenObserver()
        runtime_service = ContainmentService(
            audit=audit,
            event_sink=observer.observe,
        )
        runtime_service.register(
            "adversarial-agent",
            containment=containment,
        )

        report = runtime_service.contain("adversarial-agent")
        assert report.complete
        assert report.certified
        assert report.external_verified
        assert report.containment_requested_at is not None
        assert report.provider_applied_at is not None
        assert report.independently_verified_at is not None
        assert report.containment_requested_at <= report.provider_applied_at <= report.independently_verified_at
        assert report.enforcement_latency_seconds is not None
        assert report.enforcement_latency_seconds >= 0
        assert "enforcer:linux-ebpf-egress:verified" in report.stages
        assert runtime.state is RuntimeState.CONTAINED
        assert not runtime.lease_valid(lease)

        observed_types = [observation.observed_event_type for observation in observer.snapshot()]
        assert observed_types[:2] == ["agent_registered", "containment_requested"]
        assert "capability_revoked" in observed_types
        assert "containment_enforced" in observed_types
        assert "containment_certified" in observed_types

        observed_containment = [
            observation
            for observation in observer.snapshot()
            if observation.observed_event_type == "containment_certified"
        ]
        assert observed_containment
        assert observed_containment[-1].agent_id == "adversarial-agent"
        assert observed_containment[-1].containment_epoch == report.epoch

        assert child.stdin is not None
        child.stdin.write("go\n")
        child.stdin.flush()

        _wait_for_file(attempted)
        _wait_for_file(blocked)
        assert not escaped.exists()
        assert report.enforcement_latency_seconds < 1.0

        with pytest.raises(socket.timeout):
            server.accept()

        child.wait(timeout=3)
        assert child.returncode == 0

        ok, reason = audit.verify()
        assert ok, reason
        events = [
            json.loads(line)
            for line in audit_path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        containment_events = [event for event in events if event["event_type"] == "containment"]
        assert containment_events
        assert containment_events[-1]["external_verified"] is True
        assert containment_events[-1]["complete"] is True
        record_proof("post_containment_egress")
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
        for p in (marker, blocked, escaped, attempted, marker_dir / "ready"):
            p.unlink(missing_ok=True)
        try:
            pin_dir.rmdir()
        except OSError:
            pass
        try:
            marker_dir.rmdir()
        except OSError:
            pass


def test_controller_containment_kills_hostile_cgroup_process():
    if sys.platform != "linux":
        pytest.skip("Linux cgroup integration test")
    if os.geteuid() != 0:
        pytest.skip("requires root for cgroup operations")
    if os.environ.get("AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS") != "1":
        pytest.skip("set AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1 to run")

    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").exists():
        pytest.skip("cgroup v2 is unavailable")

    group = root / f"agent-containment-process-test-{os.getpid()}"
    marker_dir = Path(tempfile.mkdtemp(prefix="agent-containment-process-"))
    ready = marker_dir / "ready"
    heartbeat = marker_dir / "heartbeat"
    child_code = (
        "import os,sys,time\n"
        "group=sys.argv[1]\n"
        "with open(group + '/cgroup.procs','w') as f: f.write(str(os.getpid()))\n"
        "open(sys.argv[2],'w').write('ready')\n"
        "while True:\n"
        "    open(sys.argv[3],'w').write(str(time.time()))\n"
        "    time.sleep(0.05)\n"
    )
    child = None
    try:
        group.mkdir()
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(group), str(ready), str(heartbeat)]
        )
        _wait_for_file(ready)
        _wait_for_file(heartbeat)

        runtime = Runtime("hostile-agent")
        containment = ContainmentController(
            runtime,
            process_containment=LinuxCgroupProcessContainment(group),
        )
        service = ContainmentService()
        service.register("hostile-agent", containment=containment)

        report = service.contain("hostile-agent")

        assert report.complete
        assert runtime.state is RuntimeState.CONTAINED
        assert "processes_contained" in report.stages
        child.wait(timeout=3)
        assert child.returncode is not None
        record_proof("cgroup_workload_containment")
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        try:
            group.rmdir()
        except OSError:
            pass
        for p in (ready, heartbeat):
            p.unlink(missing_ok=True)
        try:
            marker_dir.rmdir()
        except OSError:
            pass
