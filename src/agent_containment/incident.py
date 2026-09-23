import hashlib
import json
from dataclasses import asdict

from .containment import ContainmentReport
from .models import Action, Decision


def incident_digest(actions: list[Action], decisions: list[Decision]) -> str:
    payload = json.dumps(
        {"actions": [asdict(a) for a in actions], "decisions": [asdict(d) for d in decisions]},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def containment_digest(report: ContainmentReport) -> str:
    payload = json.dumps(asdict(report), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()


def proof_record(
    agent_id: str,
    actions: list[Action],
    decisions: list[Decision],
    contained: bool,
    containment: ContainmentReport | None = None,
) -> dict:
    record = {
        "schema": "agent-containment/incident/v1",
        "agent_id": agent_id,
        "contained": contained,
        "actions": [asdict(a) for a in actions],
        "decisions": [asdict(d) for d in decisions],
        "sha256": incident_digest(actions, decisions),
    }
    if containment is not None:
        record["containment"] = {
            "agent_id": containment.agent_id,
            "epoch": containment.epoch,
            "stages": list(containment.stages),
            "failures": list(containment.failures),
            "complete": containment.complete,
            "sha256": containment_digest(containment),
        }
    return record
