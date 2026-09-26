"""Structured proof evidence emitted by adversarial tests.

The proof file is an execution artifact, not an attestation. Tests record a
proof only after their assertions for that proof have succeeded.
"""

from __future__ import annotations

import json
import os
from pathlib import Path


def record_proof(proof_id: str) -> None:
    path_value = os.environ.get("AGENT_CONTAINMENT_PROOF_FILE")
    if not path_value:
        return

    path = Path(path_value)
    path.parent.mkdir(parents=True, exist_ok=True)

    existing: list[str] = []
    if path.exists():
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(loaded, list) and all(isinstance(item, str) for item in loaded):
                existing = loaded
        except (OSError, json.JSONDecodeError):
            existing = []

    if proof_id not in existing:
        existing.append(proof_id)

    path.write_text(json.dumps(sorted(existing), indent=2) + "\n", encoding="utf-8")
