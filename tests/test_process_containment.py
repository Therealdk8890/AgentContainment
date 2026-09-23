import os
import pytest
from agent_containment.process import LinuxCgroupProcessContainment, NoopProcessContainment

def test_noop_process_containment_is_safe():
    assert NoopProcessContainment().contain() == 0

def test_linux_cgroup_requires_real_cgroup_v2_path():
    if os.name != "posix":
        pytest.skip("POSIX-only")
    with pytest.raises((RuntimeError, ValueError)):
        LinuxCgroupProcessContainment("/definitely/not/a/cgroup")
