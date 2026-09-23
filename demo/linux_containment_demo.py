"""End-to-end Linux containment demonstration.

SAFE DEMO: the child only connects to a localhost test server and creates
temporary marker files. No real infrastructure is contacted.

Run as root on Linux after building the eBPF artifacts:
    sudo python demo/linux_containment_demo.py
"""
from __future__ import annotations

import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from agent_containment.audit import AuditLog
from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.egress_enforcement import LinuxEbpfEgressEnforcer
from agent_containment.linux_supervisor import LinuxCgroupSupervisor
from agent_containment.models import Action
from agent_containment.policy import PolicyEngine, SequenceRule
from agent_containment.process import LinuxCgroupProcessContainment
from agent_containment.runtime import Runtime


def wait_for(path: Path, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.02)
    raise RuntimeError(f"timed out waiting for {path}")


def main() -> int:
    if sys.platform != "linux" or os.geteuid() != 0:
        print("ERROR: run this demo as root on Linux.")
        return 2

    cgroup_root = Path("/sys/fs/cgroup")
    if not (cgroup_root / "cgroup.controllers").exists():
        print("ERROR: cgroup v2 is required.")
        return 2

    controller_bin = Path("build/agent_containment_ebpf_ctl")
    bpf_object = Path("build/agent_containment_egress.bpf.o")
    if not controller_bin.is_file() or not bpf_object.is_file():
        print("ERROR: build eBPF artifacts first with scripts/build_ebpf.sh")
        return 2

    group = cgroup_root / f"agent-containment-demo-{os.getpid()}"
    pin_dir = Path("/sys/fs/bpf") / f"agent-containment-demo-{os.getpid()}"
    work = Path(tempfile.mkdtemp(prefix="agent-containment-demo-"))
    ready = work / "ready"
    connected = work / "connected"
    blocked = work / "blocked"
    escaped = work / "escaped"
    audit_path = work / "audit.jsonl"

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    server.settimeout(2.0)
    host, port = server.getsockname()

    child_code = (
        "import socket,sys,time\n"
        "group,host,port,ready,connected,go,blocked,escaped=sys.argv[1:]\n"
        "open(ready,'w').write('ready')\n"
        "s=socket.create_connection((host,int(port)),timeout=2)\n"
        "s.sendall(b'pre-containment')\n"
        "open(connected,'w').write('connected')\n"
        "s.close()\n"
        "open(go,'w').write('waiting')\n"
        "while not __import__('os').path.exists(go + '.release'): time.sleep(.02)\n"
        "try:\n"
        "  s=socket.create_connection((host,int(port)),timeout=1)\n"
        "  s.sendall(b'post-containment')\n"
        "  open(escaped,'w').write('escaped')\n"
        "  s.close()\n"
        "except OSError:\n"
        "  open(blocked,'w').write('blocked')\n"
        "time.sleep(10)\n"
    )

    child = None
    try:
        group.mkdir()
        pin_dir.mkdir()

        child = subprocess.Popen(
            [
                sys.executable, "-c", child_code,
                str(group), host, str(port), str(ready), str(connected),
                str(work / "release"), str(blocked), str(escaped),
            ],
        )

        # The controller, not the child, establishes workload membership.
        supervisor = LinuxCgroupSupervisor(cgroup_root)
        supervisor.attach_pid(group, child.pid)
        wait_for(ready)
        wait_for(connected)

        conn, _ = server.accept()
        assert conn.recv(64) == b"pre-containment"
        conn.close()

        runtime = Runtime("adversarial-agent")
        audit = AuditLog(audit_path)
        egress = LinuxEbpfEgressEnforcer(
            str(controller_bin), str(bpf_object), str(group), str(pin_dir)
        )
        containment = ContainmentController(
            runtime,
            CapabilitySet({"filesystem.write", "database.write", "network.egress"}),
            process_containment=LinuxCgroupProcessContainment(group),
            kernel_egress=egress,
        )
        policy = PolicyEngine(
            sequence_rules=[
                SequenceRule(
                    "download-upload-delete",
                    ("download_file", "upload_file", "delete_file"),
                )
            ]
        )
        service = ContainmentService(audit)
        service.register("adversarial-agent", containment=containment, policy=policy)

        print("AGENTCONTAINMENT LINUX ADVERSARIAL DEMO")
        print("=" * 44)
        for action_id, operation, resource in (
            ("a1", "download_file", "workspace/report.txt"),
            ("a2", "upload_file", "localhost/report.txt"),
            ("a3", "delete_file", "workspace/report.txt"),
        ):
            decision = service.authorize(
                Action("adversarial-agent", action_id, operation, resource, risk=10)
            )
            print(f"[{action_id}] {operation:<18} {decision.decision.value.upper()}")
            if decision.decision.value == "halt":
                print(f"      {decision.reason}")
                break

        report = service.contain("adversarial-agent")
        print("\n--- CONTAINMENT ---")
        print(f"Runtime:       {runtime.state.value.upper()}")
        print(f"Epoch:         {runtime.epoch}")
        print(f"Capabilities:  {sorted(containment.capabilities.capabilities)}")
        print(f"Egress:        {'BLOCKED' if 'kernel_egress_contained' in report.stages else 'FAILED'}")

        # Release the child so it attempts one post-containment connection.
        release = work / "release"
        release.with_name(release.name + ".release").write_text("go")
        wait_for(blocked, timeout=3.0)
        assert not escaped.exists()
        print("Post-containment egress: BLOCKED")

        # Now exercise the process kill boundary explicitly.
        supervisor.contain(group)
        child.wait(timeout=3)
        print("Process containment: KILLED")

        valid, message = audit.verify()
        print(f"Audit:         {'VALID' if valid else 'INVALID'}")
        print(f"Audit detail:  {message}")

        success = (
            report.complete
            and "runtime_fenced" in report.stages
            and "capabilities_revoked" in report.stages
            and "kernel_egress_contained" in report.stages
            and child.returncode is not None
            and not escaped.exists()
            and valid
        )
        print(f"\nATTACK RESULT: {'CONTAINED' if success else 'INCOMPLETE'}")
        return 0 if success else 1
    finally:
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        subprocess.run(
            [str(controller_bin), "detach", str(pin_dir)],
            check=False,
            capture_output=True,
            text=True,
        )
        try:
            group.rmdir()
        except OSError:
            pass
        server.close()
        for path in (ready, connected, blocked, escaped, audit_path, work / "release", work / "release.release"):
            path.unlink(missing_ok=True)
        try:
            pin_dir.rmdir()
        except OSError:
            pass
        try:
            work.rmdir()
        except OSError:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
