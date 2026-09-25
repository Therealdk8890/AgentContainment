"""Hardened Unix-domain control transport for the controller plane."""
from __future__ import annotations

import json
import os
import socket
import struct
from pathlib import Path
from threading import Event
from typing import Any

from .control import ContainmentService
from .linux_supervisor import LinuxCgroupSupervisor
from .models import Action


class ControlProtocolError(ValueError):
    pass


class UnixControlServer:
    """Newline-delimited JSON protocol over a controller-owned Unix socket."""

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
            peer_uid, peer_pid = self._peer_credentials(conn)
            if not self._peer_allowed(peer_uid):
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
                response = self.handle(request, peer_uid=peer_uid, peer_pid=peer_pid)
            except (json.JSONDecodeError, ControlProtocolError, KeyError, ValueError) as exc:
                response = {"ok": False, "error": str(exc)}
            except Exception:
                response = {"ok": False, "error": "internal_error"}
            self._send(conn, response)

    def handle(self, request: Any, *, peer_uid: int | None = None,
               peer_pid: int | None = None) -> dict[str, Any]:
        if not isinstance(request, dict):
            return {"ok": False, "error": "request must be an object"}
        command = request.get("command")

        if command == "register":
            self._require_privileged(peer_uid)
            agent_id = self._agent_id(request)
            workload_pid = request.get("workload_pid")
            if workload_pid is not None:
                if not isinstance(workload_pid, int) or isinstance(workload_pid, bool) or workload_pid <= 0:
                    raise ControlProtocolError("workload_pid must be a positive integer")
                if self.service.cgroup_supervisor is None:
                    raise ControlProtocolError("workload_pid requires a configured cgroup supervisor")

            # Validate all request fields before mutating controller state.
            # Registration is a security boundary: malformed workload
            # parameters must not leave behind a live agent or partially-created
            # identity state.
            runtime = self.service.register(agent_id, metadata=self._metadata(request))
            try:
                cgroup_path = self.service.create_workload(agent_id) if self.service.cgroup_supervisor is not None else None
                if workload_pid is not None:
                    self.service.attach_workload(agent_id, workload_pid)
                token = self.service.issue_identity_token(agent_id, peer_pid=workload_pid) if workload_pid is not None else None
            except Exception:
                # Do not leave a registered active runtime behind when workload
                # admission fails. The containment controller is still
                # controller-owned; unregistering here removes the incomplete
                # registration without attempting to infer external cgroup state.
                self.service.unregister(agent_id)
                raise
            return {
                "ok": True,
                "agent_id": agent_id,
                "state": runtime.state.value,
                "identity_token": token,
                "cgroup_path": cgroup_path,
            }

        if command == "status":
            agent_id = self._agent_id(request)
            return {"ok": True, "agent_id": agent_id,
                    "state": self.service.status(agent_id).value}

        if command == "authorize":
            agent_id = self._agent_id(request)
            identity_token = request.get("identity_token")
            if not isinstance(identity_token, str) or not identity_token:
                raise ControlProtocolError("identity_token is required")
            action_id = request.get("action_id")
            operation = request.get("operation")
            resource = request.get("resource")
            risk = request.get("risk", 0)
            if not isinstance(action_id, str) or not action_id or len(action_id) > 256:
                raise ControlProtocolError("action_id must be a non-empty string of at most 256 characters")
            if not isinstance(operation, str) or not operation or len(operation) > 256:
                raise ControlProtocolError("operation must be a non-empty string of at most 256 characters")
            if not isinstance(resource, str) or not resource or len(resource) > 4096:
                raise ControlProtocolError("resource must be a non-empty string of at most 4096 characters")
            if not isinstance(risk, int) or isinstance(risk, bool) or not 0 <= risk <= 100:
                raise ControlProtocolError("risk must be an integer from 0 to 100")
            membership = None
            if self.service.identity_cgroup(agent_id) is not None:
                membership = LinuxCgroupSupervisor.pid_in_cgroup
            decision = self.service.authorize(
                Action(agent_id, action_id, operation, resource, risk=risk),
                identity_token=identity_token,
                peer_pid=peer_pid,
                cgroup_membership=membership,
            )
            return {"ok": True, "agent_id": agent_id, "action_id": action_id,
                    "decision": decision.decision.value, "reason": decision.reason,
                    "timestamp": decision.timestamp}

        if command == "contain":
            self._require_privileged(peer_uid)
            agent_id = self._agent_id(request)
            report = self.service.contain(agent_id)
            return {"ok": True, "agent_id": agent_id,
                    "state": self.service.status(agent_id).value,
                    "containment": {"epoch": report.epoch, "stages": list(report.stages),
                                    "failures": list(report.failures), "complete": report.complete}}

        if command == "report":
            agent_id = self._agent_id(request)
            report = self.service.report(agent_id)
            if report is None:
                return {"ok": True, "agent_id": agent_id, "containment": None}
            return {"ok": True, "agent_id": agent_id,
                    "containment": {"epoch": report.epoch, "stages": list(report.stages),
                                    "failures": list(report.failures), "complete": report.complete}}

        if command == "snapshot":
            return {"ok": True, "agents": {
                agent_id: state.value for agent_id, state in self.service.snapshot().items()
            }}

        raise ControlProtocolError("unsupported command")

    @staticmethod
    def _agent_id(request: dict[str, Any]) -> str:
        agent_id = request.get("agent_id")
        if not isinstance(agent_id, str) or not agent_id or len(agent_id) > 256:
            raise ControlProtocolError("agent_id must be a non-empty string of at most 256 characters")
        return agent_id

    @staticmethod
    def _optional_cgroup(request: dict[str, Any]) -> str | None:
        value = request.get("cgroup_path")
        if value is None:
            return None
        if not isinstance(value, str) or not value or len(value) > 4096:
            raise ControlProtocolError("cgroup_path must be a non-empty string of at most 4096 characters")
        path = Path(value)
        if not path.is_absolute() or not path.is_dir():
            raise ControlProtocolError("cgroup_path must be an existing absolute directory")
        return str(path.resolve())

    @staticmethod
    def _metadata(request: dict[str, Any]) -> dict[str, str]:
        metadata = request.get("metadata", {})
        if not isinstance(metadata, dict) or any(
            not isinstance(k, str) or not isinstance(v, str) for k, v in metadata.items()
        ):
            raise ControlProtocolError("metadata must be a string-to-string object")
        return metadata

    def _require_privileged(self, uid: int | None) -> None:
        # Fail closed when no privileged UID policy was configured. The
        # controller must never accidentally expose register/contain authority
        # to every local peer merely because the daemon was started without
        # optional ACL flags.
        allowed = self.privileged_uids if self.privileged_uids is not None else self.allowed_uids
        if allowed is None:
            allowed = {os.geteuid()}
        if uid is None or uid not in allowed:
            raise ControlProtocolError("forbidden_command")

    def _peer_credentials(self, conn: socket.socket) -> tuple[int | None, int | None]:
        if not hasattr(socket, "SO_PEERCRED"):
            return None, None
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            pid, uid, _gid = struct.unpack("3i", raw)
            return uid, pid
        except (OSError, struct.error):
            return None, None

    def _peer_allowed(self, uid: int | None) -> bool:
        if self.allowed_uids is None:
            return True
        return uid is not None and uid in self.allowed_uids

    @staticmethod
    def _send(conn: socket.socket, response: dict[str, Any]) -> None:
        conn.sendall((json.dumps(response, sort_keys=True) + "\n").encode("utf-8"))
