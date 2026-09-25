import os
import subprocess
import sys
import time
from pathlib import Path

import pytest


pytestmark = pytest.mark.integration


def test_non_root_process_uses_delegated_cgroup_subtree():
    """Prove a delegated non-root process can manage only its own subtree."""
    if sys.platform != "linux":
        pytest.skip("Linux cgroup v2 integration test")
    if os.geteuid() != 0:
        pytest.skip("requires root to establish the delegation boundary")
    if os.environ.get("AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS") != "1":
        pytest.skip("set AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1 to run")

    cgroup_root = Path("/sys/fs/cgroup")
    if not (cgroup_root / "cgroup.controllers").exists():
        pytest.skip("cgroup v2 is unavailable")

    parent = cgroup_root / f"agent-containment-delegation-{os.getpid()}"
    marker = Path(f"/tmp/agent-containment-delegation-{os.getpid()}")
    nobody = 65534
    child = None
    workload = None

    child_code = r"""
import os
import subprocess
import sys
import time
from pathlib import Path

from agent_containment.linux_supervisor import LinuxCgroupSupervisor

parent = Path(sys.argv[1])
marker = Path(sys.argv[2])
marker.write_text("started", encoding="utf-8")

supervisor = LinuxCgroupSupervisor("auto")
expected = parent / "agents"
if supervisor._delegated_root() != expected:
    raise SystemExit(
        f"auto root mismatch: {supervisor._delegated_root()} != {expected}"
    )

agent = supervisor.create_agent("delegated-agent")
if not agent.is_dir():
    raise SystemExit("agent cgroup was not created")

workload = subprocess.Popen(
    [sys.executable, "-c", "import time; time.sleep(30)"]
)
supervisor.attach_pid(agent, workload.pid)

if not supervisor.pid_in_cgroup(workload.pid, agent):
    raise SystemExit("workload was not attached to delegated child cgroup")

if not supervisor.is_populated(agent):
    raise SystemExit("delegated child cgroup is not populated")

supervisor.contain(agent)

try:
    workload.wait(timeout=3)
except subprocess.TimeoutExpired:
    workload.kill()
    workload.wait(timeout=3)
    raise SystemExit("cgroup.kill did not contain workload")

if supervisor.is_populated(agent):
    raise SystemExit("agent cgroup remained populated after containment")

supervisor.remove(agent)
marker.write_text("passed", encoding="utf-8")
"""

    try:
        parent.mkdir()
        # Simulate the ownership established by a real systemd Delegate=yes
        # boundary. The root test process performs the one-time delegation;
        # the child then exercises the subtree entirely as nobody.
        os.chown(parent, nobody, nobody)
        parent.chmod(0o755)

        # Move the child into the delegated parent before it drops privileges.
        child = subprocess.Popen(
            [sys.executable, "-c", child_code, str(parent), str(marker)],
            preexec_fn=lambda: os.setuid(nobody),
        )
        (parent / "cgroup.procs").write_text(f"{child.pid}\n")
        child.wait(timeout=10)

        assert child.returncode == 0
        assert marker.read_text(encoding="utf-8") == "passed"
        assert not (parent / "agents").exists()
    finally:
        if workload is not None and workload.poll() is None:
            workload.kill()
            workload.wait(timeout=3)
        if child is not None and child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        for path in (parent / "agents", parent):
            try:
                path.rmdir()
            except OSError:
                pass
        marker.unlink(missing_ok=True)
