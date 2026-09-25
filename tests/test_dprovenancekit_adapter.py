from __future__ import annotations

import sys
import types
from contextlib import contextmanager

from agent_containment.dprovenancekit_adapter import (
    DProvenanceKitSink,
    DProvenanceKitUnavailable,
)
from agent_containment.governance_event import GovernanceEvent
from agent_containment.provenance import provenance_record


def _install_fake_dpk(monkeypatch, recorded):
    instrument = types.ModuleType("dprovenancekit.instrument")

    @contextmanager
    def traced_run(**kwargs):
        recorded.append(("run.start", kwargs))
        try:
            yield
        finally:
            recorded.append(("run.end", kwargs))

    def record_event(event_type, attributes):
        recorded.append((event_type, attributes))
        return "event-id"

    instrument.traced_run = traced_run
    instrument.record_event = record_event

    package = types.ModuleType("dprovenancekit")
    package.__path__ = []
    monkeypatch.setitem(sys.modules, "dprovenancekit", package)
    monkeypatch.setitem(sys.modules, "dprovenancekit.instrument", instrument)


def _event() -> GovernanceEvent:
    return GovernanceEvent(
        event_id="evt-1",
        event_type="containment.enforced",
        timestamp=1234.5,
        agent_id="agent-7",
        trace_id="trace-1",
        run_id="run-1",
        action_id="action-1",
        policy_decision_id="decision-1",
        incident_id="incident-1",
        containment_epoch=4,
        reason="policy violation",
        attributes={"enforcement": "cilium", "result": "blocked"},
    )


def test_adapter_maps_governance_identity(monkeypatch):
    recorded = []
    _install_fake_dpk(monkeypatch, recorded)
    sink = DProvenanceKitSink(context_id="incident-1")

    with sink.run():
        sink.append(provenance_record(_event()))

    event = next(item for item in recorded if item[0] == "agent_containment.containment.enforced")
    attrs = event[1]
    assert attrs["event_id"] == "evt-1"
    assert attrs["run_id"] == "run-1"
    assert attrs["containment_epoch"] == 4
    assert attrs["attributes"]["result"] == "blocked"


def test_adapter_requires_active_run(monkeypatch):
    recorded = []
    _install_fake_dpk(monkeypatch, recorded)
    sink = DProvenanceKitSink()
    record = provenance_record(_event())

    try:
        sink.append(record)
    except RuntimeError as exc:
        assert "active sink.run" in str(exc)
    else:
        raise AssertionError("append must reject an inactive DPK run")


def test_adapter_is_best_effort_for_controller(monkeypatch):
    recorded = []
    _install_fake_dpk(monkeypatch, recorded)
    sink = DProvenanceKitSink()
    emitter = sink.emitter()

    assert emitter.emit(_event()) is False


def test_adapter_can_be_used_as_event_sink(monkeypatch):
    recorded = []
    _install_fake_dpk(monkeypatch, recorded)
    sink = DProvenanceKitSink()

    with sink.run():
        assert sink(_event()) is True

    assert any(
        item[0] == "agent_containment.containment.enforced"
        for item in recorded
    )


def test_missing_optional_dependency(monkeypatch):
    monkeypatch.delitem(sys.modules, "dprovenancekit.instrument", raising=False)
    monkeypatch.setitem(sys.modules, "dprovenancekit", types.ModuleType("dprovenancekit"))

    try:
        DProvenanceKitSink()
    except DProvenanceKitUnavailable as exc:
        assert "DProvenanceKitPython" in str(exc)
    else:
        raise AssertionError("missing DPK must be reported explicitly")
