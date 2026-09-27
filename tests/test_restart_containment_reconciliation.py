import pytest

from agent_containment.control import ContainmentService
from agent_containment.containment import ContainmentController
from agent_containment.egress_enforcement import LinuxEbpfExternalEnforcer
from agent_containment.incident_state import IncidentRegistry, IncidentState
from agent_containment.runtime import Runtime, RuntimeState


def _ebpf_controller(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    cgroup = tmp_path / "agent"
    cgroup.mkdir()
    controller = tmp_path / "ctl"
    controller.write_text("")
    obj = tmp_path / "policy.o"
    obj.write_text("")
    pin_dir = tmp_path / "pin"
    pin_dir.mkdir()
    (pin_dir / "egress_link").write_text("pinned")
    return LinuxEbpfExternalEnforcer(controller, obj, cgroup, pin_dir), pin_dir


def test_restart_reconciles_external_containment_before_recovery(monkeypatch, tmp_path):
    incident_path = tmp_path / "incidents.json"
    first_enforcer, pin_dir = _ebpf_controller(tmp_path)
    calls = []

    class Result:
        returncode = 0
        stderr = ""
        stdout = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(cmd) > 1 and cmd[1] == "detach":
            pin_dir.joinpath("egress_link").unlink(missing_ok=True)
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fake_run
    )

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register(
        "agent-restart-proof",
        containment=ContainmentController(
            Runtime("agent-restart-proof"), enforcers=[first_enforcer]
        ),
    )
    report = first.contain("agent-restart-proof")
    assert report.epoch == 1
    assert report.external_verified
    assert pin_dir.joinpath("egress_link").exists()

    # Recreate the surviving external-enforcement artifact after the first
    # controller's test fixture has established containment. A fresh
    # controller instance must reconcile that existing boundary.
    pin_dir.joinpath("egress_link").write_text("pinned")
    second_enforcer = LinuxEbpfExternalEnforcer(
        tmp_path / "ctl", tmp_path / "policy.o", tmp_path / "agent", pin_dir
    )
    second = ContainmentService(incidents=IncidentRegistry(incident_path))
    restarted_runtime = Runtime("agent-restart-proof")
    restarted_runtime.restore_contained(1)
    runtime = second.register(
        "agent-restart-proof",
        containment=ContainmentController(
            restarted_runtime, enforcers=[second_enforcer]
        ),
    )

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    before = len(calls)
    auth = second.issue_recovery_authorization("agent-restart-proof")
    assert len(calls) > before
    assert calls[-1][1] == "verify"
    assert runtime.epoch == 1
    assert runtime.state is RuntimeState.CONTAINED

    assert second.recover("agent-restart-proof", auth) == 2
    assert runtime.state is RuntimeState.ACTIVE


def test_restart_blocks_recovery_when_external_containment_cannot_reconcile(
    monkeypatch, tmp_path
):
    incident_path = tmp_path / "incidents.json"
    first_enforcer, pin_dir = _ebpf_controller(tmp_path / "shared")
    second_enforcer = LinuxEbpfExternalEnforcer(
        tmp_path / "shared" / "ctl",
        tmp_path / "shared" / "policy.o",
        tmp_path / "shared" / "agent",
        pin_dir,
    )

    class Result:
        returncode = 0
        stderr = ""
        stdout = ""

    def fake_run(cmd, **kwargs):
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fake_run
    )

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register(
        "agent-restart-block",
        containment=ContainmentController(
            Runtime("agent-restart-block"), enforcers=[first_enforcer]
        ),
    )
    assert first.contain("agent-restart-block").complete

    def fail_restart_verify(cmd, **kwargs):
        if len(cmd) > 1 and cmd[1] == "verify" and str(second_enforcer._pin_dir) in cmd:
            return type(
                "Result",
                (),
                {
                    "returncode": 1,
                    "stderr": "wrong target",
                    "stdout": "",
                },
            )()
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fail_restart_verify
    )

    second = ContainmentService(incidents=IncidentRegistry(incident_path))
    restarted_runtime = Runtime("agent-restart-block")
    restarted_runtime.restore_contained(1)
    runtime = second.register(
        "agent-restart-block",
        containment=ContainmentController(
            restarted_runtime, enforcers=[second_enforcer]
        ),
    )

    with pytest.raises(RuntimeError, match="reconciliation failed"):
        second.issue_recovery_authorization("agent-restart-block")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    incident = second.incident("agent-restart-block")
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
