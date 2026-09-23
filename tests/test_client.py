import json
import socket
import threading

from agent_containment.client import EnforcementClient
from agent_containment.control import ContainmentService
from agent_containment.transport import UnixControlServer


def test_client_round_trip(tmp_path):
    path = tmp_path / "control.sock"
    server = UnixControlServer(ContainmentService(), path)
    server.start()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        client = EnforcementClient(str(path))
        assert client.register("demo")["ok"]
        assert client.status("demo")["state"] == "active"
        result = client.contain("demo")
        assert result["ok"] and result["state"] == "contained"
    finally:
        server.close()
        thread.join(timeout=1)


def test_client_rejects_non_object_response(tmp_path):
    path = tmp_path / "control.sock"
    server = UnixControlServer(ContainmentService(), path)
    server.start()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.connect(str(path))
            sock.sendall((json.dumps(["not", "an", "object"]) + "\n").encode())
            response = json.loads(sock.recv(4096))
            assert response["ok"] is False
    finally:
        server.close()
