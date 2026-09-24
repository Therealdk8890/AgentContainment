"""Durable controller fence state used across controller restarts.

The fence is written before runtime containment. If incident persistence later
fails, the fence still tells a fresh controller to fail closed. The fence is
deliberately separate from incident proof/audit state.
"""
from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path
from threading import RLock


@dataclass(frozen=True)
class FenceRecord:
    agent_id: str
    containment_epoch: int


class RuntimeFenceRegistry:
    """Persist controller-owned containment intent independently of incidents."""

    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path is not None else None
        self._records: dict[str, FenceRecord] = {}
        self._lock = RLock()
        self._load()

    @property
    def persistence_available(self) -> bool:
        return self.path is not None

    def prepare(self, agent_id: str, containment_epoch: int) -> FenceRecord:
        if not agent_id:
            raise ValueError("agent_id must be non-empty")
        if containment_epoch < 0:
            raise ValueError("containment_epoch must be non-negative")
        with self._lock:
            record = FenceRecord(agent_id, containment_epoch)
            candidate = dict(self._records)
            candidate[agent_id] = record
            self._persist_locked(candidate)
            self._records = candidate
            return record

    def get(self, agent_id: str) -> FenceRecord | None:
        with self._lock:
            return self._records.get(agent_id)

    def clear(self, agent_id: str) -> None:
        with self._lock:
            if agent_id not in self._records:
                return
            candidate = dict(self._records)
            del candidate[agent_id]
            self._persist_locked(candidate)
            self._records = candidate

    def _load(self) -> None:
        if self.path is None or not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            records = raw.get("records")
            if not isinstance(records, list):
                raise ValueError("runtime fence records must be a list")
            loaded: dict[str, FenceRecord] = {}
            for item in records:
                if not isinstance(item, dict):
                    raise ValueError("runtime fence record must be an object")
                record = FenceRecord(**item)
                if record.agent_id in loaded:
                    raise ValueError(f"duplicate runtime fence: {record.agent_id}")
                loaded[record.agent_id] = record
            self._records = loaded
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise RuntimeError(f"invalid runtime fence registry: {exc}") from exc

    def _persist_locked(self, records: dict[str, FenceRecord]) -> None:
        if self.path is None:
            raise RuntimeError("durable runtime fence persistence is unavailable")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": 1,
            "records": [asdict(record) for record in records.values()],
        }
        fd, temp_name = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=str(self.path.parent)
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temp_name, self.path)
        finally:
            if os.path.exists(temp_name):
                os.unlink(temp_name)
