from agent_containment.incident_state import IncidentRegistry, IncidentState


def test_containment_fact_survives_controller_restart(tmp_path):
    path = tmp_path / "incidents.json"
    first = IncidentRegistry(path)
    original = first.record_containment(
        "inc-1", "agent-1", 7, reason="runtime fence requested"
    )

    second = IncidentRegistry(path)
    recovered = second.get("inc-1")

    assert recovered == original
    assert recovered.state is IncidentState.CONTAINED
    assert recovered.containment_epoch == 7


def test_missing_registry_does_not_invent_history(tmp_path):
    registry = IncidentRegistry(tmp_path / "missing.json")

    assert registry.all() == ()
    assert registry.get("inc-unknown") is None


def test_proof_degradation_survives_restart_without_changing_epoch(tmp_path):
    path = tmp_path / "incidents.json"
    first = IncidentRegistry(path)
    original = first.record_containment("inc-2", "agent-2", 4)
    degraded = first.mark_proof_degraded(
        "inc-2", reason="proof persistence unavailable"
    )

    second = IncidentRegistry(path)
    recovered = second.get("inc-2")

    assert degraded.state is IncidentState.PROOF_DEGRADED
    assert recovered.state is IncidentState.PROOF_DEGRADED
    assert recovered.containment_epoch == original.containment_epoch == 4
    assert recovered.created_at == original.created_at


def test_corrupt_registry_fails_closed(tmp_path):
    path = tmp_path / "incidents.json"
    path.write_text("{not-json", encoding="utf-8")

    try:
        IncidentRegistry(path)
    except RuntimeError as exc:
        assert "invalid incident registry" in str(exc)
    else:
        raise AssertionError("corrupt incident registry was accepted")
