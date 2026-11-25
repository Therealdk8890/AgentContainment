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
    path = tmp_path / "agent-1.scope"
    path.mkdir()
    _cgroup(path)
    enforcer = CgroupV2Enforcer({"agent-1": path})

    # A different cgroup now lives at the bound path. On cgroupfs (kernfs) a
    # recreated cgroup always gets a new inode number. On ordinary filesystems
    # rmdir + mkdir can reuse the inode within one coarse ctime tick, which made
    # this test fail intermittently (e.g. on ext4), so keep the old directory
    # alive under another name: the replacement then has a distinct inode.
    path.rename(tmp_path / "agent-1.scope.old")
    path.mkdir()
    (path / "cgroup.kill").write_text("")
    (path / "cgroup.events").write_text("populated 0\nfrozen 0\n")

    assert enforcer.verify_released("agent-1").status is EnforcementStatus.VERIFICATION_FAILED
