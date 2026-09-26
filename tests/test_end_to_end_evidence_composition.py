from __future__ import annotations

from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.evidence_chain import IncidentEvidenceChain
from agent_containment.incident_evidence import IncidentEvidenceRecorder
from agent_containment.proof_receipt import ReceiptVerifier
from agent_containment.provenance import InMemoryProvenanceSink, ProvenanceEmitter
from agent_containment.regression import RegressionFixtureBuilder
from agent_containment.warden_observer import WardenObserver


SECRET = b"end-to-end-composition-secret"


class VerifiedEnforcer:
    name = "test-provider"

    def contain(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "containment active")

    def verify_contained(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "containment verified")

    def release(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "released")

    def verify_released(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "release verified")


def test_containment_evidence_composes_across_all_downstream_boundaries():
    events = []
    provenance_sink = InMemoryProvenanceSink()
    provenance = ProvenanceEmitter(provenance_sink)
    evidence = IncidentEvidenceRecorder(IncidentEvidenceChain())
    warden = WardenObserver()

    def event_sink(event):
        events.append(event)
        assert provenance.emit(event)
        evidence.record_governance_event(event)
        warden.observe(event)

    service = ContainmentService(event_sink=event_sink)
    runtime = service.register("agent-1")
    service.configure_containment(
        "agent-1",
        ContainmentController(runtime, enforcers=[VerifiedEnforcer()]),
    )

    report = service.contain("agent-1")
    incident = service.incident("agent-1")
    assert incident is not None
    assert report.certified
    assert report.durable

    containment_events = [
        event for event in events if event.event_type == "containment_enforced"
    ]
    assert len(containment_events) == 1
    containment_event = containment_events[0]
    assert containment_event.agent_id == report.agent_id
    assert containment_event.incident_id == incident.incident_id
    assert containment_event.containment_epoch == report.epoch

    provenance_record = next(
        record
        for record in provenance_sink.records
        if record.event_id == containment_event.event_id
    )
    assert provenance_record.agent_id == containment_event.agent_id
    assert provenance_record.incident_id == containment_event.incident_id
    assert provenance_record.containment_epoch == containment_event.containment_epoch

    observation = next(
        observation
        for observation in warden.snapshot()
        if observation.observed_event_id == containment_event.event_id
    )
    assert observation.agent_id == containment_event.agent_id
    assert observation.incident_id == containment_event.incident_id
    assert observation.containment_epoch == containment_event.containment_epoch

    evidence.verify()
    evidence_node = next(
        node
        for node in evidence.chain.nodes
        if node.event_id == containment_event.event_id
    )
    assert evidence_node.incident_id == incident.incident_id
    assert evidence_node.containment_epoch == report.epoch

    receipt = report.to_receipt(
        SECRET,
        execution_id="execution-1",
        policy_id="policy-1",
        receipt_id="receipt:agent-1:1",
    )
    assert receipt.verify(SECRET)
    assert ReceiptVerifier(SECRET).verify(receipt)
    assert receipt.payload["agent_id"] == incident.agent_id
    assert receipt.payload["epoch"] == incident.containment_epoch

    fixture = RegressionFixtureBuilder().build(
        incident_id=incident.incident_id,
        agent_id=incident.agent_id,
        agent_version=None,
        task="contain hostile execution",
        context={"policy": {"denied_operations": ["exfiltrate"], "max_risk": 80}},
        action_sequence=("exfiltrate",),
        policy_decision="HALT",
        evidence_refs=tuple(node.event_id for node in evidence.chain.nodes),
        containment_result="certified",
        expected_future_behavior="HALT before exfiltrate",
    )
    assert fixture.verify_identity()
    assert incident.incident_id in fixture.incident_id
