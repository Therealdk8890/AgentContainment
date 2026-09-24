"""Controller-owned tamper-evident JSONL audit chain."""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from threading import RLock
from time import time
from typing import Any

GENESIS = "0" * 64


def _canonical(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class AuditLog:
    """Append-only hash chain.

    The chain is tamper-evident, not externally immutable: an attacker who can
    delete the file can remove history. Verification therefore fails closed
    before appending to an already-corrupt chain.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self._lock = RLock()

    def record(self, event_type: str, *, agent_id: str, action_id: str | None = None,
               decision: str | None = None, reason: str | None = None,
               timestamp: float | None = None, **fields: Any) -> dict[str, Any]:
        if not isinstance(event_type, str) or not event_type:
            raise ValueError("event_type must be non-empty")
        if not isinstance(agent_id, str) or not agent_id:
            raise ValueError("agent_id must be non-empty")
        with self._lock:
            if self.path.exists():
                ok, verification_reason = self.verify()
                if not ok:
                    raise RuntimeError(
                        f"refusing to append to invalid audit chain: {verification_reason}"
                    )
                lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
            else:
                lines = []

            previous_hash = GENESIS
            if lines:
                previous_hash = json.loads(lines[-1])["hash"]

            event: dict[str, Any] = {
                "version": 1,
                "sequence": 1 if not lines else len(lines) + 1,
                "timestamp": time() if timestamp is None else timestamp,
                "event_type": event_type,
                "agent_id": agent_id,
                "action_id": action_id,
                "decision": decision,
                "reason": reason,
                "previous_hash": previous_hash,
                **fields,
            }
            event["hash"] = hashlib.sha256(_canonical(event)).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n")
        return event

    def verify(self) -> tuple[bool, str]:
        with self._lock:
            if not self.path.exists():
                return True, "empty audit log"
            expected_previous = GENESIS
            expected_sequence = 1
            try:
                lines = self.path.read_text(encoding="utf-8").splitlines()
                for line in lines:
                    if not line.strip():
                        continue
                    event = json.loads(line)
                    stored = event.pop("hash")
                    if event.get("sequence") != expected_sequence:
                        return False, f"sequence mismatch at {expected_sequence}"
                    if event.get("previous_hash") != expected_previous:
                        return False, f"previous hash mismatch at sequence {expected_sequence}"
                    actual = hashlib.sha256(_canonical(event)).hexdigest()
                    if stored != actual:
                        return False, f"hash mismatch at sequence {expected_sequence}"
                    expected_previous = stored
                    expected_sequence += 1
            except (OSError, json.JSONDecodeError, KeyError, TypeError):
                return False, "malformed audit log"
            return True, "audit chain valid"
