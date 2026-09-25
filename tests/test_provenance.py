from agent_containment.governance_event import GovernanceEvent
from agent_containment.provenance import InMemoryProvenanceSink, ProvenanceEmitter, provenance_record


def event():
    return GovernanceEvent(
        event_id="evt-1", event_type="containment_enforced", timestamp=123.5,
        agent_id="agent-1", trace_id="trace-1", run_id="run-1", action_id="action-1",
        policy_decision_id="decision-1", incident_id="incident-1", containment_epoch=7,
        reason="policy violation", attributes={"provider": "ebpf", "verified": True},
    )


def test_provenance_snapshot_preserves_governance_identity():
    record = provenance_record(event())
    assert record.schema == "agent-containment/governance-event/v1"
    assert record.event_id == "evt-1"
    assert record.containment_epoch == 7
    assert record.to_dict()["attributes"] == {"provider": "ebpf", "verified": True}


def test_in_memory_sink_exposes_immutable_record_view():
    sink = InMemoryProvenanceSink()
    assert ProvenanceEmitter(sink).emit(event()) is True
    records = sink.records
    assert isinstance(records, tuple)
    assert records[0].event_id == "evt-1"
    payload = records[0].to_dict()
    payload["attributes"]["verified"] = False
    assert records[0].to_dict()["attributes"]["verified"] is True


class FailingSink:
    def append(self, record):
        raise RuntimeError("provenance unavailable")


def test_provenance_failure_is_downstream_only():
    assert ProvenanceEmitter(FailingSink()).emit(event()) is False
