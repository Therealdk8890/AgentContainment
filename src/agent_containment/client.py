"""Client for the AgentContainment Unix control protocol."""
from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import Any


class UnixControlClient:
    """Newline-delimited JSON client for the controller Unix socket."""

    def __init__(self, path: str | Path, *, timeout: float = 2.0, identity_token: str | None = None):
        self.path = str(path)
        self.timeout = timeout
        self.identity_token = identity_token

    def request(self, command: str, **fields: Any) -> dict[str, Any]:
        payload = {"command": command, **fields}
        data = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(self.timeout)
            sock.connect(self.path)
            sock.sendall(data)
            response = bytearray()
            while len(response) <= 64 * 1024:
                chunk = sock.recv(min(4096, 64 * 1024 + 1 - len(response)))
                if not chunk:
                    break
                response.extend(chunk)
                if b"\n" in chunk:
                    break
        if not response:
            raise RuntimeError("control daemon returned no response")
        try:
            result = json.loads(bytes(response).split(b"\n", 1)[0].decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise RuntimeError("invalid control daemon response") from exc
        if not isinstance(result, dict):
            raise RuntimeError("invalid control daemon response")
        return result

    def register(self, agent_id: str, metadata: dict[str, str] | None = None) -> dict[str, Any]:
        result = self.request("register", agent_id=agent_id, metadata=metadata or {})
        if result.get("ok") and isinstance(result.get("identity_token"), str):
            self.identity_token = result["identity_token"]
        return result

    def status(self, agent_id: str) -> dict[str, Any]:
        return self.request("status", agent_id=agent_id)

    def contain(self, agent_id: str) -> dict[str, Any]:
        return self.request("contain", agent_id=agent_id)

    def report(self, agent_id: str) -> dict[str, Any]:
        return self.request("report", agent_id=agent_id)

    def authorize(
        self,
        agent_id: str,
        action_id: str,
        operation: str,
        resource: str,
        *,
        risk: int = 0,
    ) -> dict[str, Any]:
        if not self.identity_token:
            raise RuntimeError("register the agent first to obtain an identity token")
        return self.request(
            "authorize",
            agent_id=agent_id,
            action_id=action_id,
            operation=operation,
            resource=resource,
            risk=risk,
            identity_token=self.identity_token,
        )


class EnforcementClient(UnixControlClient):
    """Public client name for the standalone enforcement control plane."""
