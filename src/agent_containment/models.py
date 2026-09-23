from dataclasses import dataclass, field
from enum import Enum
from time import time
from typing import Any

class DecisionType(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    PAUSE = "pause"
    HALT = "halt"
    CONTAIN = "contain"

@dataclass(frozen=True)
class Action:
    agent_id: str
    action_id: str
    operation: str
    resource: str
    risk: int = 0
    metadata: dict[str, Any] = field(default_factory=dict)

@dataclass(frozen=True)
class Decision:
    action_id: str
    decision: DecisionType
    reason: str
    timestamp: float = field(default_factory=time)
