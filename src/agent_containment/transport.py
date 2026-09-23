"""Hardened Unix-domain control transport for the controller plane."""
from __future__ import annotations

import json
import os
import socket
from threading import Event
from pathlib import Path
from typing import Any

from .control import ContainmentService


class ControlProtocolError(ValueError):
    pass


class UnixControlServer:
    """Small newline-delimited JSON protocol over a filesystem Unix socket.

    The socket is controller-owned and defaults to mode 0660. Commands are
    deliberately narrow: register, status, contain, report, and snapshot.
    """

    def __init__(self, service: ContainmentService, path: str | os.PathLike[str],
                 *, mode: int = 0o660, max_message_bytes: int = 64 * 1024,
                 allowed_uids: set[int] | None = None,
                 privileged_uids: set[int] | None = None):
        self.service = service
        self.path = Path(path)
        self.mode = mode
        self.max_message_bytes = max_message_bytes
        self.allowed_uids = allowed_uids
        self.privileged_uids = privileged_uids
        self._sock: socket.socket | None = None
        self._stop = Event()

    def start(self) -> None:
        if not hasattr(socket, "AF_UNIX"):
            raise RuntimeError("Unix-domain sockets are unavailable on this platform")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass
        self._stop.clear()
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(str(self.path))
        os.chmod(self.path, self.mode)
        self._sock.listen(16)

    def serve_forever(self, *, stop_event: Event | None = None) -> None:
        """Serve requests until close() or the supplied stop event is set."""
        if self._sock is None:
            raise RuntimeError("server is not started")
        self._sock.settimeout(0.25)
        event = stop_event or self._stop
        while not event.is_set():
            try:
                self.serve_once()
            except socket.timeout:
                continue
            except OSError:
                if event.is_set() or self._sock is None:
                    break
                raise

    def close(self) -> None:
        self._stop.set()
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        try:
            self.path.unlink()
        except FileNotFoundError:
            pass

    def serve_once(self) -> None:
        if self._sock is None:
            raise RuntimeError("server is not started")
        conn, _ = self._sock.accept()
        with conn:
            if not self._peer_allowed(conn):
                self._send(conn, {"ok": False, "error": "unauthorized_peer"})
                return
            conn.settimeout(2.0)
            data = bytearray()
            while len(data) <= self.max_message_bytes:
                chunk = conn.recv(min(4096, self.max_message_bytes + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if b"\n" in chunk:
                    break
            if len(data) > self.max_message_bytes:
                self._send(conn, {"ok": False, "error": "message_too_large"})
                return
            line = bytes(data).split(b"\n", 1)[0].strip()
            if not line:
                self._send(conn, {"ok": False, "error": "empty_request"})
                return
            try:
                request = json.loads(line)
                response = self.handle(request, peer_uid=self._peer_uid(conn))
            except (json.JSONDecodeError, ControlProtocolError, KeyError, ValueError) as exc:
                response = {"ok": False, "error": str(exc)}
            except Exception:
                response = {"ok": False, "error": "internal_error"}
            self._send(conn, response)

    def handle(self, request: Any, *, peer_uid: int | None = None) -> dict[str, Any]:
        if not isinstance(request, dict):
            return {"ok": False, "error": "request must be an object"}
        command = request.get("command")
        if command == "register":
            self._require_privileged(peer_uid)
            agent_id = self._agent_id(request)
            runtime = self.service.register(
                agent_id, metadata=self._metadata(request)
            )
            return {"ok": True, "agent_id": agent_id, "state": runtime.state.value}
        if command == "status":
            agent_id = self._agent_id(request)
            return {"ok": True, "agent_id": agent_id,
                    "state": self.service.status(agent_id).value}
        if command == "contain":
            self._require_privileged(peer_uid)
            agent_id = self._agent_id(request)
            report = self.service.contain(agent_id)
            return {"ok": True, "agent_id": agent_id,
                    "state": self.service.status(agent_id).value,
                    "containment": {
                        "epoch": report.epoch,
                        "stages": list(report.stages),
                        "failures": list(report.failures),
                        "complete": report.complete,
                    }}
        if command == "report":
            agent_id = self._agent_id(request)
            report = self.service.report(agent_id)
            if report is None:
                return {"ok": True, "agent_id": agent_id, "containment": None}
            return {"ok": True, "agent_id": agent_id,
                    "containment": {
                        "epoch": report.epoch,
                        "stages": list(report.stages),
                        "failures": list(report.failures),
                        "complete": report.complete,
                    }}
        if command == "snapshot":
            return {"ok": True, "agents": {
                agent_id: state.value
                for agent_id, state in self.service.snapshot().items()
            }}
        raise ControlProtocolError("unsupported command")

    @staticmethod
    def _agent_id(request: dict[str, Any]) -> str:
        agent_id = request.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id or len(agent_id) > 256:
            raise ControlProtocolError("agent_id must be a non-empty string of at most 256 characters")
        return agent_id

    @staticmethod
    def _metadata(request: dict[str, Any]) -> dict[str, str]:
        metadata = request.get("metadata", {})
        if not isinstance(metadata, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items()
        ):
            raise ControlProtocolError("metadata must be a string-to-string object")
        return metadata

    def _require_privileged(self, uid: int | None) -> None:
        if self.privileged_uids is not None:
            allowed = self.privileged_uids
        elif self.allowed_uids is not None:
            allowed = self.allowed_uids
        else:
            return
        if uid is None or uid not in allowed:
            raise ControlProtocolError("forbidden_command")

    def _peer_uid(self, conn: socket.socket) -> int | None:
        if not hasattr(socket, "SO_PEERCRED"):
            return None
        try:
            import struct
            raw = conn.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                struct.calcsize("3i"),
            )
            _pid, uid, _gid = struct.unpack("3i", raw)
            return uid
        except (OSError, struct.error):
            return None

    def _peer_allowed(self, conn: socket.socket) -> bool:
        if self.allowed_uids is None:
            return True
        if not hasattr(socket, "SO_PEERCRED"):
            return False
        try:
            import struct
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
            return uid in self.allowed_uids
        except (OSError, struct.error):
            return False

    @staticmethod
    def _send(conn: socket.socket, response: dict[str, Any]) -> None:
        conn.sendall((json.dumps(response, sort_keys=True) + "\n").encode("utf-8"))
