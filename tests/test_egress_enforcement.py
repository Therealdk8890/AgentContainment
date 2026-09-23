from pathlib import Path
from agent_containment.egress_enforcement import LinuxCgroupEgressEnforcer, NoopKernelEgressEnforcer

def test_noop_kernel_enforcer_does_not_mutate_state():
    assert NoopKernelEgressEnforcer().contain() is None

def test_linux_enforcer_sets_controller_owned_deny_state(tmp_path: Path):
    state = tmp_path / "egress.state"
    LinuxCgroupEgressEnforcer(str(state)).contain()
    assert state.read_text() == "deny\n"
