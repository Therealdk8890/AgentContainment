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


def test_pid_start_time_parser_handles_spaces_and_parentheses(monkeypatch):
    class FakePath:
        def __init__(self, value):
            self.value = value

        def is_file(self):
            return True

        def read_text(self):
            # comm contains spaces and parentheses; start time is field 22.
            return "123 (worker (agent) name) S " + " ".join(str(i) for i in range(3, 23))

    monkeypatch.setattr(
        "agent_containment.linux_supervisor.Path",
        FakePath,
    )

    assert LinuxCgroupSupervisor.pid_start_time_ticks(123) == 22
