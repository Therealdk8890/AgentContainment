from pathlib import Path

from agent_containment.egress_enforcement import (
    LinuxCgroupEgressEnforcer,
    LinuxEbpfEgressEnforcer,
    NoopKernelEgressEnforcer,
)


def test_noop_kernel_enforcer_does_not_mutate_state():
    assert NoopKernelEgressEnforcer().contain() is None


def test_linux_enforcer_sets_controller_owned_deny_state(tmp_path: Path):
    state = tmp_path / "egress.state"
    LinuxCgroupEgressEnforcer(str(state)).contain()
    assert state.read_text() == "deny\n"


def test_linux_ebpf_enforcer_invokes_controller(monkeypatch, tmp_path: Path):
    cgroup = tmp_path / "agent"
    cgroup.mkdir()
    controller = tmp_path / "ctl"
    controller.write_text("")
    obj = tmp_path / "policy.o"
    obj.write_text("")
    pin_dir = tmp_path / "pin"

    calls = []

    class Result:
        returncode = 0
        stderr = ""
        stdout = ""

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fake_run
    )

    enforcer = LinuxEbpfEgressEnforcer(
        controller, obj, cgroup, pin_dir
    )
    enforcer.contain()

    assert calls == [(
        [
            str(controller),
            "attach",
            str(obj),
            str(cgroup),
            str(pin_dir),
        ],
        {
            "check": True,
            "timeout": 10.0,
            "capture_output": True,
            "text": True,
        },
    )]
    assert pin_dir.is_dir()
