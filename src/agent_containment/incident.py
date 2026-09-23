import hashlib
import json
from dataclasses import asdict
from .models import Action, Decision

def incident_digest(actions: list[Action], decisions: list[Decision]) -> str:
    payload = json.dumps({"actions": [asdict(a) for a in actions], "decisions": [asdict(d) for d in decisions]}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode()).hexdigest()

def proof_record(agent_id: str, actions: list[Action], decisions: list[Decision], contained: bool) -> dict:
    return {
        "schema": "agent-containment/incident/v0",
        "agent_id": agent_id,
        "contained": contained,
        "actions": [asdict(a) for a in actions],
        "decisions": [asdict(d) for d in decisions],
        "sha256": incident_digest(actions, decisions),
    }
