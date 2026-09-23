import pytest
from agent_containment.linux_supervisor import LinuxCgroupSupervisor

def test_safe_name_rejects_path_traversal():
    with pytest.raises(ValueError):
        LinuxCgroupSupervisor._safe_name("../escape")
    with pytest.raises(ValueError):
        LinuxCgroupSupervisor._safe_name("a/b")
    with pytest.raises(ValueError):
        LinuxCgroupSupervisor._safe_name("a\\b")
    with pytest.raises(ValueError):
        LinuxCgroupSupervisor._safe_name("a\x00b")

def test_safe_name_accepts_agent_id():
    assert LinuxCgroupSupervisor._safe_name("agent-01") == "agent-01"

def test_attach_pid_requires_positive_pid(tmp_path):
    with pytest.raises(ValueError):
        LinuxCgroupSupervisor.attach_pid(tmp_path, 0)

def test_is_populated_parses_cgroup_events(tmp_path):
    (tmp_path / "cgroup.events").write_text("populated 1\nfrozen 0\n")
    assert LinuxCgroupSupervisor.is_populated(tmp_path)

def test_is_populated_empty_for_missing_events(tmp_path):
    assert not LinuxCgroupSupervisor.is_populated(tmp_path)
