"""Controller-owned human review lifecycle for paused actions.

A verifier can require review, but review never grants runtime authority by
itself. The controller owns approval, expiry, and escalation semantics.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from time import time


class ReviewState(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    EXPIRED = "expired"
    ESCALATED = "escalated"


@dataclass(frozen=True)
class ReviewRequest:
    review_id: str
    agent_id: str
    action_id: str
    requested_at: float
    deadline: float
    state: ReviewState = ReviewState.PENDING

    @property
    def expired(self) -> bool:
        return time() >= self.deadline

    def current_state(self, now: float | None = None) -> ReviewState:
        if self.state is not ReviewState.PENDING:
            return self.state
        if (time() if now is None else now) >= self.deadline:
            return ReviewState.EXPIRED
        return ReviewState.PENDING
