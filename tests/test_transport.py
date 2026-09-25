import pytest
import json
import os
import socket
import threading

from agent_containment.control import ContainmentService
from agent_containment.transport import ControlProtocolError, UnixControlServer


def _roundtrip(server, path, payload):
    thread = threading.Thread(target=server.serve_once)
    thread.start()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(str(path))
        client.sendall((json.dumps(payload) + "\n").encode())
        data = client.recv(4096)
    thread.join(timeout=2)
    assert not thread.is_alive()
    return json.loads(data.decode())


def test_protocol_register_status_and_contain(tmp_path):
    path = tmp_path / "controller.sock"
    class FakeSupervisor:
        def create_agent(self, agent_id):
            return tmp_path / agent_id
        def attach_pid(self, path, pid):
            return None

    server = UnixControlServer(ContainmentService(cgroup_supervisor=FakeSupervisor()), path, allowed_uids={os.getuid()}, privileged_uids={os.getuid()})
    server.start()
    try:
        register = _roundtrip(server, path, {"command": "register", "agent_id": "agent-1"})
        assert register["state"] == "active"
        assert register["identity_token"] is None
        assert register["cgroup_path"].endswith("/agent-1")
        assert _roundtrip(server, path, {"command": "status", "agent_id": "agent-1"})["state"] == "active"
        result = _roundtrip(server, path, {"command": "contain", "agent_id": "agent-1"})
        assert result["state"] == "contained"
        assert result["containment"]["complete"] is True
    finally:
        server.close()



def test_privileged_commands_fail_closed_without_uid_configuration():
    server = UnixControlServer(ContainmentService(), "/tmp/agent-containment-test.sock")
    response = server.handle(
        {"command": "contain", "agent_id": "agent-1"},
        peer_uid=os.getuid(),
    )
    assert response["ok"] is False
    assert response["error"] == "forbidden_command"

def test_protocol_rejects_bad_request():
    server = UnixControlServer(ContainmentService(), "/tmp/agent-containment-test.sock")
    response = server.handle(["not", "an", "object"])
    assert response["ok"] is False


def test_peer_uid_policy_accepts_current_uid(tmp_path):
    path = tmp_path / "controller.sock"
    server = UnixControlServer(ContainmentService(), path, allowed_uids={os.getuid()})
    server.start()
    try:
        response = _roundtrip(server, path, {"command": "snapshot"})
        assert response["ok"] is True
    finally:
        server.close()


def test_peer_uid_policy_rejects_wrong_uid(tmp_path):
    path = tmp_path / "controller.sock"
    wrong_uid = os.getuid() + 1
    server = UnixControlServer(ContainmentService(), path, allowed_uids={wrong_uid})
    server.start()
    try:
        response = _roundtrip(server, path, {"command": "snapshot"})
        assert response == {"ok": False, "error": "unauthorized_peer"}
    finally:
        server.close()

def test_peer_uid_can_read_but_cannot_contain_without_privilege(tmp_path):
    path = tmp_path / "controller.sock"
    server = UnixControlServer(
        ContainmentService(),
        path,
        allowed_uids={os.getuid()},
        privileged_uids={os.getuid() + 1},
    )
    server.start()
    try:
        register = _roundtrip(server, path, {"command": "register", "agent_id": "agent-1"})
        assert register["ok"] is False
        assert register["error"] == "forbidden_command"
    finally:
        server.close()


def test_transport_workload_registration_issues_bound_token_and_authorizes(tmp_path, monkeypatch):
    path = tmp_path / "controller.sock"

    class FakeSupervisor:
        def create_agent(self, agent_id):
            return tmp_path / agent_id

        def attach_pid(self, cgroup_path, pid):
            self.attached = (str(cgroup_path), pid)

    monkeypatch.setattr(
        "agent_containment.transport.LinuxCgroupSupervisor.pid_in_cgroup",
        lambda pid, cgroup_path: pid == os.getpid(),
    )

    server = UnixControlServer(
        ContainmentService(cgroup_supervisor=FakeSupervisor()),
        path,
        allowed_uids={os.getuid()},
        privileged_uids={os.getuid()},
    )
    server.start()
    try:
        register = _roundtrip(
            server,
            path,
            {
                "command": "register",
                "agent_id": "agent-transport",
                "workload_pid": os.getpid(),
            },
        )
        assert register["ok"] is True
        assert isinstance(register["identity_token"], str)
        assert register["identity_token"]

        decision = _roundtrip(
            server,
            path,
            {
                "command": "authorize",
                "agent_id": "agent-transport",
                "action_id": "a1",
                "operation": "read",
                "resource": "workspace/report.txt",
                "identity_token": register["identity_token"],
            },
        )
        assert decision["ok"] is True
        assert decision["decision"] == "allow"
    finally:
        server.close()


def test_transport_denies_token_from_wrong_peer_pid(tmp_path, monkeypatch):
    path = tmp_path / "controller.sock"

    class FakeSupervisor:
        def create_agent(self, agent_id):
            return tmp_path / agent_id

        def attach_pid(self, cgroup_path, pid):
            return None

    monkeypatch.setattr(
        "agent_containment.transport.LinuxCgroupSupervisor.pid_in_cgroup",
        lambda pid, cgroup_path: True,
    )

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    service.register("agent-transport")
    service.create_workload("agent-transport")
    token = service.issue_identity_token("agent-transport", peer_pid=os.getpid() + 1)

    server = UnixControlServer(service, path, allowed_uids={os.getuid()})
    server.start()
    try:
        decision = _roundtrip(
            server,
            path,
            {
                "command": "authorize",
                "agent_id": "agent-transport",
                "action_id": "a1",
                "operation": "read",
                "resource": "workspace/report.txt",
                "identity_token": token,
            },
        )
        assert decision["ok"] is True
        assert decision["decision"] == "deny"
        assert "authenticated" in decision["reason"]
    finally:
        server.close()


def test_transport_denies_token_when_peer_is_outside_workload(tmp_path, monkeypatch):
    path = tmp_path / "controller.sock"

    class FakeSupervisor:
        def create_agent(self, agent_id):
            return tmp_path / agent_id

        def attach_pid(self, cgroup_path, pid):
            return None

    monkeypatch.setattr(
        "agent_containment.transport.LinuxCgroupSupervisor.pid_in_cgroup",
        lambda pid, cgroup_path: False,
    )

    server = UnixControlServer(
        ContainmentService(cgroup_supervisor=FakeSupervisor()),
        path,
        allowed_uids={os.getuid()},
        privileged_uids={os.getuid()},
    )
    server.start()
    try:
        register = _roundtrip(
            server,
            path,
            {
                "command": "register",
                "agent_id": "agent-transport",
                "workload_pid": os.getpid(),
            },
        )
        assert register["ok"] is True

        decision = _roundtrip(
            server,
            path,
            {
                "command": "authorize",
                "agent_id": "agent-transport",
                "action_id": "a1",
                "operation": "read",
                "resource": "workspace/report.txt",
                "identity_token": register["identity_token"],
            },
        )
        assert decision["ok"] is True
        assert decision["decision"] == "deny"
        assert "authenticated" in decision["reason"]
    finally:
        server.close()

def test_register_rejects_invalid_workload_pid_without_registration(tmp_path):
    path = tmp_path / "controller.sock"

    class FakeSupervisor:
        def create_agent(self, agent_id):
            raise AssertionError("workload must not be created for invalid input")

        def attach_pid(self, cgroup_path, pid):
            raise AssertionError("workload must not be attached for invalid input")

    service = ContainmentService(cgroup_supervisor=FakeSupervisor())
    server = UnixControlServer(
        service,
        path,
        allowed_uids={os.getuid()},
        privileged_uids={os.getuid()},
    )
    with pytest.raises(ControlProtocolError, match="positive integer"):
        server.handle(
            {"command": "register", "agent_id": "bad-workload", "workload_pid": True},
            peer_uid=os.getuid(),
        )

    assert service.snapshot() == {}


def test_privileged_commands_fail_closed_without_uid_configuration(tmp_path):
    path = tmp_path / "controller.sock"
    server = UnixControlServer(ContainmentService(), path)
    with pytest.raises(ControlProtocolError, match="forbidden_command"):
        server.handle(
            {"command": "contain", "agent_id": "agent-1"},
            peer_uid=os.getuid() + 1,
        )


def test_transport_returns_clean_timeout_for_stalled_peer(tmp_path):
    server_sock, client_sock = socket.socketpair()
    server_sock.settimeout(0.01)

    class FakeListener:
        def accept(self):
            return server_sock, None

    server = UnixControlServer(ContainmentService(), tmp_path / "controller.sock")
    server._sock = FakeListener()
    try:
        thread = threading.Thread(target=server.serve_once)
        thread.start()
        data = client_sock.recv(4096)
        thread.join(timeout=1)
        assert not thread.is_alive()
        assert json.loads(data.decode()) == {"ok": False, "error": "request_timeout"}
    finally:
        client_sock.close()
        server_sock.close()
