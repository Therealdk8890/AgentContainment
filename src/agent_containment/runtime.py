from enum import Enum

class RuntimeState(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    HALTED = "halted"
    CONTAINED = "contained"

class Runtime:
    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.state = RuntimeState.ACTIVE

    def halt(self) -> None:
        self.state = RuntimeState.HALTED

    def contain(self) -> None:
        self.state = RuntimeState.CONTAINED

    @property
    def can_execute(self) -> bool:
        return self.state is RuntimeState.ACTIVE
