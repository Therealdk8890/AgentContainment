"""Client for the AgentContainment Unix control protocol."""
from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


class UnixControlClient:
    def __init__(self, path: str | Path, *, timeout: float = 2.0):
        self.path = str(path)
        self.timeout = timeout

    def request(self, command: str, **fields: Any) -> dict[str, Any]:
        payload = {"command": command, **fields}
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            sock.sendall((json.dumps(payload, sort_keys=True) + "\n").encode("utf-8"))
            data = sock.recv(64 * 1024)
        response = json.loads(data.decode("utf-8"))
        if not isinstance(response, dict):
            raise ValueError("invalid controller response")
        return response

    def authorize(self, agent_id: str, action_id: str, operation: str, resource: str, *, risk: int = 0) -> dict[str, Any]:
        return self.request(
            "authorize", agent_id=agent_id, action_id=action_id,
            operation=operation, resource=resource, risk=risk,
        )
