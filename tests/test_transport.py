import json
import os
import socket
import struct
import threading

from agent_containment.control import ContainmentService
from agent_containment.transport import UnixControlServer


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
    server = UnixControlServer(ContainmentService(), path)
    server.start()
    try:
        assert _roundtrip(server, path, {"command": "register", "agent_id": "agent-1"})["state"] == "active"
        assert _roundtrip(server, path, {"command": "status", "agent_id": "agent-1"})["state"] == "active"
        result = _roundtrip(server, path, {"command": "contain", "agent_id": "agent-1"})
        assert result["state"] == "contained"
        assert result["containment"]["complete"] is True
    finally:
        server.close()


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
