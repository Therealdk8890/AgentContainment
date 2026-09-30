import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from agent_containment.cgroup_enforcer import CgroupV2Enforcer
from agent_containment.containment import ContainmentController
from agent_containment.linux_supervisor import LinuxCgroupSupervisor
from agent_containment.runtime import Runtime
from agent_containment.runtime_observation import RuntimeObservationSource


pytestmark = pytest.mark.integration


def test_real_cgroup_kill_is_independently_observed_and_epoch_bound():
    """Prove external cgroup kill against a real workload and bind evidence to its epoch."""
    if sys.platform != "linux":
        pytest.skip("Linux cgroup v2 integration test")
    if os.geteuid() != 0:
        pytest.skip("requires root to create and populate a dedicated cgroup")
    if os.environ.get("AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS") != "1":
        pytest.skip("set AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1 to run")
    root = Path("/sys/fs/cgroup")
    if not (root / "cgroup.controllers").exists():
        pytest.skip("cgroup v2 is unavailable")

    root_cgroup = root / f"agent-containment-real-kill-{os.getpid()}"
    workload = None
    supervisor = LinuxCgroupSupervisor(root_cgroup)

    try:
        agent_id = "real-kill-agent"
        cgroup = supervisor.create_agent(agent_id)
        runtime = Runtime(agent_id)
        enforcer = CgroupV2Enforcer({agent_id: cgroup})
        controller = ContainmentController(runtime, enforcers=[enforcer])

        # Ignore cooperative termination signals so the test exercises the
        # external cgroup.kill boundary rather than a graceful shutdown path.
        workload_code = (
            "import signal, time; "
            "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
            "signal.signal(signal.SIGINT, signal.SIG_IGN); "
            "time.sleep(60)"
        )
        workload = subprocess.Popen([sys.executable, "-c", workload_code])
        supervisor.attach_pid(cgroup, workload.pid)

        assert supervisor.pid_in_cgroup(workload.pid, cgroup)
        assert supervisor.is_populated(cgroup)
        workload_pid = workload.pid

        report = controller.contain()

        # The workload is killed by the external enforcement boundary, not by
        # the test process sending a signal to the workload.
        workload.wait(timeout=3)
        assert workload.returncode is not None
        assert workload.returncode < 0
        assert not supervisor.is_populated(cgroup)

        assert report.agent_id == agent_id
        assert report.epoch == 1
        assert report.external_verified is True
        assert report.certified is True
        assert "enforcer:cgroup-v2:verified" in report.stages
        assert report.failures == ()

        # Independent post-kill observations come from the kernel-backed
        # cgroup state and /proc, not from the controller's in-memory state.
        assert not Path(f"/proc/{workload_pid}").exists()
        observation = RuntimeObservationSource().observe(runtime)
        assert observation.epoch == report.epoch
        assert observation.state == "contained"
        assert observation.can_execute is False
        assert observation.verify_integrity()
        assert RuntimeObservationSource().matches(observation, runtime)
    finally:
        if workload is not None and workload.poll() is None:
            workload.kill()
            workload.wait(timeout=3)
        if root_cgroup.exists():
            for child in sorted(root_cgroup.iterdir(), reverse=True):
                try:
                    child.rmdir()
                except OSError:
                    pass
            try:
                root_cgroup.rmdir()
            except OSError:
                pass
