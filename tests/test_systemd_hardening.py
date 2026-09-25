from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
SYSTEMD_DIR = REPO_ROOT / "systemd"


def _unit(path: str) -> str:
    return (SYSTEMD_DIR / path).read_text(encoding="utf-8")


def _value(unit: str, key: str) -> str:
    for line in unit.splitlines():
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1].strip()
    raise AssertionError(f"{key}= not found")


def test_controller_uses_dedicated_service_identity():
    controller = _unit("agentcontainment.service")
    agent = _unit("agentcontainment-agent-example.service")

    controller_uid = _value(controller, "User")
    controller_gid = _value(controller, "Group")
    agent_uid = _value(agent, "User")
    agent_gid = _value(agent, "Group")

    assert controller_uid == "agentcontainment"
    assert controller_gid == "agentcontainment"
    assert controller_uid != agent_uid
    assert controller_gid != agent_gid


def test_controller_service_has_boundary_hardening():
    controller = _unit("agentcontainment.service")

    assert "NoNewPrivileges=yes" in controller
    assert "ProtectHome=yes" in controller
    assert "ProtectSystem=strict" in controller
    assert "ProtectKernelTunables=yes" in controller
    assert "ProtectKernelModules=yes" in controller
    assert "ProtectControlGroups=no" in controller
    assert "RestrictSUIDSGID=yes" in controller
    assert "UMask=0077" in controller
    assert "RuntimeDirectory=agentcontainment" in controller
    assert "RuntimeDirectoryMode=0700" in controller


def test_agent_admission_requires_controller_startup():
    agent = _unit("agentcontainment-agent-example.service")

    assert "Requires=agentcontainment.service" in agent
    assert "After=agentcontainment.service" in agent
    assert "PartOf=agentcontainment.service" in agent
    assert "ExecStartPre=/usr/bin/test -S /run/agentcontainment/control.sock" in agent
