import json

from agent_containment.audit import AuditLog, GENESIS


def test_audit_chain_records_and_verifies(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.record("agent_registered", agent_id="a1", timestamp=1.0)
    second = log.record(
        "authorization_decision",
        agent_id="a1",
        action_id="x1",
        decision="allow",
        reason="policy allowed",
        timestamp=2.0,
    )

    assert first["previous_hash"] == GENESIS
    assert second["previous_hash"] == first["hash"]
    assert second["sequence"] == 2
    assert log.verify() == (True, "audit chain valid")


def test_audit_chain_detects_tampering(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("agent_registered", agent_id="a1", timestamp=1.0)
    log.record("authorization_decision", agent_id="a1", action_id="x1", decision="deny", timestamp=2.0)

    events = [json.loads(line) for line in path.read_text().splitlines()]
    events[0]["agent_id"] = "attacker"
    path.write_text("\n".join(json.dumps(event) for event in events) + "\n")

    ok, reason = log.verify()
    assert not ok
    assert "hash mismatch" in reason


def test_audit_chain_detects_reorder_and_deletion(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("one", agent_id="a1", timestamp=1.0)
    log.record("two", agent_id="a1", timestamp=2.0)
    log.record("three", agent_id="a1", timestamp=3.0)

    events = [json.loads(line) for line in path.read_text().splitlines()]
    path.write_text("\n".join(json.dumps(event) for event in [events[1], events[0]]) + "\n")
    ok, reason = log.verify()
    assert not ok
    assert ("sequence mismatch" in reason) or ("previous hash mismatch" in reason) or ("hash mismatch" in reason)

    path.write_text("\n".join(json.dumps(event) for event in [events[0], events[2]]) + "\n")
    ok, reason = log.verify()
    assert not ok
    assert ("sequence mismatch" in reason) or ("previous hash mismatch" in reason)


def test_empty_audit_log_is_valid(tmp_path):
    assert AuditLog(tmp_path / "missing.jsonl").verify() == (True, "empty audit log")
