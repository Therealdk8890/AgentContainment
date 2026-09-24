from agent_containment.cgroup_enforcer import CgroupV2Enforcer
from agent_containment.enforcer import EnforcementStatus


def _cgroup(tmp_path, populated="0"):
    (tmp_path / "cgroup.kill").write_text("")
    (tmp_path / "cgroup.events").write_text(f"populated {populated}\nfrozen 0\n")
    return tmp_path


def test_contain_and_verify_use_authoritative_cgroup_state(tmp_path):
    path = _cgroup(tmp_path)
    enforcer = CgroupV2Enforcer({"agent-1": path})

    result = enforcer.contain("agent-1")

    assert result.status is EnforcementStatus.ENFORCED
    assert enforcer.verify_contained("agent-1").status is EnforcementStatus.ENFORCED


def test_populated_cgroup_fails_containment_verification(tmp_path):
    path = _cgroup(tmp_path, populated="1")
    enforcer = CgroupV2Enforcer({"agent-1": path})

    assert enforcer.verify_contained("agent-1").status is EnforcementStatus.VERIFICATION_FAILED


def test_release_requires_empty_cgroup(tmp_path):
    path = _cgroup(tmp_path, populated="1")
    enforcer = CgroupV2Enforcer({"agent-1": path})

    assert enforcer.release("agent-1").status is EnforcementStatus.DEGRADED

    (path / "cgroup.events").write_text("populated 0\nfrozen 0\n")
    assert enforcer.release("agent-1").status is EnforcementStatus.RELEASED
    assert enforcer.verify_released("agent-1").status is EnforcementStatus.RELEASED


def test_unknown_agent_is_not_configured(tmp_path):
    enforcer = CgroupV2Enforcer({})

    assert enforcer.contain("missing").status is EnforcementStatus.NOT_CONFIGURED


def test_missing_cgroup_state_fails_closed(tmp_path):
    enforcer = CgroupV2Enforcer({"agent-1": tmp_path})

    assert enforcer.verify_contained("agent-1").status is EnforcementStatus.VERIFICATION_FAILED
    assert enforcer.verify_released("agent-1").status is EnforcementStatus.VERIFICATION_FAILED


def test_recreated_cgroup_fails_identity_verification(tmp_path):
    path = _cgroup(tmp_path)
    enforcer = CgroupV2Enforcer({"agent-1": path})

    (path / "cgroup.kill").unlink()
    (path / "cgroup.events").unlink()
    path.rmdir()
    path.mkdir()
    (path / "cgroup.kill").write_text("")
    (path / "cgroup.events").write_text("populated 0\nfrozen 0\n")

    assert enforcer.verify_released("agent-1").status is EnforcementStatus.VERIFICATION_FAILED


def test_workload_pid_must_remain_in_bound_cgroup(tmp_path, monkeypatch):
    path = _cgroup(tmp_path)
    pid = 1234
    monkeypatch.setattr(
        "agent_containment.cgroup_enforcer.LinuxCgroupSupervisor.pid_start_time_ticks",
        lambda value: 77,
    )
    monkeypatch.setattr(
        "agent_containment.cgroup_enforcer.LinuxCgroupSupervisor.pid_in_cgroup",
        lambda value, cgroup: False,
    )
    enforcer = CgroupV2Enforcer({"agent-1": path}, {"agent-1": pid})

    result = enforcer.verify_contained("agent-1")

    assert result.status is EnforcementStatus.VERIFICATION_FAILED
    assert "outside cgroup" in result.detail


def test_workload_pid_reuse_fails_identity_verification(tmp_path, monkeypatch):
    path = _cgroup(tmp_path)
    pid = 1234
    values = iter([77, 88])
    monkeypatch.setattr(
        "agent_containment.cgroup_enforcer.LinuxCgroupSupervisor.pid_start_time_ticks",
        lambda value: next(values),
    )
    enforcer = CgroupV2Enforcer({"agent-1": path}, {"agent-1": pid})

    result = enforcer.verify_contained("agent-1")

    assert result.status is EnforcementStatus.VERIFICATION_FAILED
    assert "PID identity changed" in result.detail
