from agent_containment.evidence_chain import GENESIS, IncidentEvidenceChain


def test_chain_links_events_deterministically():
    chain = IncidentEvidenceChain()
    first = chain.append(
        event_id="evt-1",
        event_type="containment_requested",
        timestamp=10.0,
        agent_id="agent-1",
        incident_id="incident-1",
        containment_epoch=3,
        payload={"reason": "policy"},
    )
    second = chain.append(
        event_id="evt-2",
        event_type="containment_enforced",
        timestamp=11.0,
        agent_id="agent-1",
        incident_id="incident-1",
        containment_epoch=3,
        payload={"verified": True},
    )

    assert first.previous_hash == GENESIS
    assert second.previous_hash == first.node_hash
    chain.verify()
    assert chain.head_hash == second.node_hash
    assert chain.digest()


def test_payload_is_snapshotted():
    payload = {"nested": {"value": 1}}
    chain = IncidentEvidenceChain()
    node = chain.append(
        event_id="evt-1",
        event_type="detection",
        timestamp=1.0,
        agent_id="agent-1",
        payload=payload,
    )

    payload["nested"]["value"] = 999
    assert node.payload["nested"]["value"] == 1
    chain.verify()


def test_mutation_is_detected():
    chain = IncidentEvidenceChain()
    chain.append(
        event_id="evt-1",
        event_type="containment_enforced",
        timestamp=1.0,
        agent_id="agent-1",
        payload={"result": "blocked"},
    )
    node = chain.nodes[0]
    chain._nodes[0] = node.__class__(
        **{**node.__dict__, "payload": {"result": "released"}}
    )

    try:
        chain.verify()
    except ValueError as exc:
        assert "mutated" in str(exc)
    else:
        raise AssertionError("tampered evidence must fail verification")


def test_reordering_is_detected():
    chain = IncidentEvidenceChain()
    chain.append(
        event_id="evt-1",
        event_type="detection",
        timestamp=1.0,
        agent_id="agent-1",
    )
    chain.append(
        event_id="evt-2",
        event_type="containment_enforced",
        timestamp=2.0,
        agent_id="agent-1",
    )
    chain._nodes.reverse()

    try:
        chain.verify()
    except ValueError as exc:
        assert "sequence" in str(exc) or "link" in str(exc)
    else:
        raise AssertionError("reordered evidence must fail verification")


def test_snapshot_cannot_mutate_chain():
    chain = IncidentEvidenceChain()
    chain.append(
        event_id="evt-1",
        event_type="recovery_authorized",
        timestamp=1.0,
        agent_id="agent-1",
        containment_epoch=4,
    )
    snapshot = chain.snapshot()
    snapshot[0]["payload"]["injected"] = True
    chain.verify()
    assert "injected" not in chain.nodes[0].payload
