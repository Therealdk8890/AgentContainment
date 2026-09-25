"""Optional DProvenanceKit bridge for controller-owned governance events.

The core AgentContainment package stays dependency-free. This module imports
DProvenanceKitPython only when the adapter is instantiated and turns each
GovernanceEvent into a stable DPK event.

Authority boundary:
    AgentContainment CONTROL -> this adapter -> DProvenanceKit PROVENANCE

The adapter is downstream evidence only. A DPK failure must never authorize,
contain, release, or recover an agent.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from pathlib import Path
from typing import Iterator, Optional

from .governance_event import GovernanceEvent
from .provenance import ProvenanceEmitter, ProvenanceRecord, ProvenanceSink


class DProvenanceKitUnavailable(RuntimeError):
    """Raised when the optional DProvenanceKit dependency is not installed."""


class DProvenanceKitSink(ProvenanceSink):
    """Map AgentContainment provenance records into DProvenanceKit events.

    DProvenanceKitPython is deliberately imported lazily so AgentContainment's
    core install remains zero-dependency.
    """

    _active: ContextVar[bool] = ContextVar(
        "agentcontainment_dpk_sink_active", default=False
    )

    def __init__(
        self,
        *,
        db_path: Optional[str | Path] = None,
        context_id: str = "agent-containment",
        engine_name: str = "agentcontainment.control",
    ) -> None:
        try:
            from dprovenancekit.instrument import record_event, traced_run
        except ImportError as exc:
            raise DProvenanceKitUnavailable(
                "DProvenanceKitPython is required for DProvenanceKitSink; "
                "install dprovenancekit separately."
            ) from exc

        self._record_event = record_event
        self._traced_run = traced_run
        self._db_path = str(db_path) if db_path is not None else None
        self._context_id = context_id
        self._engine_name = engine_name

    @contextmanager
    def run(
        self,
        *,
        context_id: Optional[str] = None,
        db_path: Optional[str | Path] = None,
    ) -> Iterator[None]:
        """Open the downstream DPK recording boundary.

        Controller code should execute its containment lifecycle inside this
        context. The context is evidence plumbing only; it does not alter
        authorization or enforcement state.
        """
        selected_context = context_id or self._context_id
        selected_db = str(db_path) if db_path is not None else self._db_path
        token = self._active.set(True)
        try:
            kwargs = {"context_id": selected_context}
            if selected_db is not None:
                kwargs["db_path"] = selected_db
            with self._traced_run(**kwargs):
                yield
        finally:
            self._active.reset(token)

    def append(self, record: ProvenanceRecord) -> None:
        """Append one immutable AgentContainment record to the active DPK run."""
        if not self._active.get():
            raise RuntimeError(
                "DProvenanceKitSink.append() requires an active sink.run() context"
            )

        attributes = record.to_dict()
        # The DPK event type is stable and namespaced. The full record remains
        # in attributes so controller identity fields survive unchanged.
        self._record_event(
            f"agent_containment.{record.event_type}",
            attributes,
        )

    def emitter(self) -> ProvenanceEmitter:
        """Return the standard best-effort AgentContainment provenance emitter."""
        return ProvenanceEmitter(self)

    def __call__(self, event: GovernanceEvent) -> bool:
        """Controller event-sink shape for direct composition."""
        return self.emitter().emit(event)


__all__ = [
    "DProvenanceKitSink",
    "DProvenanceKitUnavailable",
]
