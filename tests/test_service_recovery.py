import pytest

from agent_containment.audit import AuditLog
from agent_containment.control import ContainmentService
from agent_containment.containment import ContainmentController
from agent_containment.incident_state import IncidentRegistry, IncidentState
from agent_containment.runtime import Runtime, RuntimeState


def test_containment_returns_even_when_audit_persistence_is_degraded(tmp_path):
    audit_path = tmp_path / "audit.jsonl"
    incident_path = tmp_path / "incidents.json"
    audit = AuditLog(audit_path)
    incidents = IncidentRegistry(incident_path)
    service = ContainmentService(audit=audit, incidents=incidents)
    service.register("agent-1")

    audit_path.write_text("{corrupt", encoding="utf-8")

    report = service.contain("agent-1")
    incident = service.incident("agent-1")

    assert report.epoch == 1
    assert report.complete
    assert incident is not None
    assert incident.state is IncidentState.PROOF_DEGRADED
    assert incident.containment_epoch == 1

    recovered = IncidentRegistry(incident_path).get(incident.incident_id)
    assert recovered is not None
    assert recovered.state is IncidentState.PROOF_DEGRADED
    assert recovered.containment_epoch == 1


def test_missing_audit_history_does_not_create_incident_history(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(audit=None, incidents=incidents)
    service.register("agent-2")

    assert service.incident("agent-2") is None


def test_restart_restores_durable_containment_as_an_admission_fence(tmp_path):
    incident_path = tmp_path / "incidents.json"
    incidents = IncidentRegistry(incident_path)

    first = ContainmentService(incidents=incidents)
    first.register("agent-restart")
    lease = first._managed("agent-restart").runtime.acquire_lease()
    assert lease is not None
    report = first.contain("agent-restart")
    assert report.epoch == 1

    recovered_incidents = IncidentRegistry(incident_path)
    second = ContainmentService(incidents=recovered_incidents)
    runtime = second.register("agent-restart")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert runtime.acquire_lease() is None
    assert runtime.execute_if_active(lease, lambda: "unsafe") is None


def test_restart_rejects_an_executable_supplied_runtime_when_contained(tmp_path):
    incident_path = tmp_path / "incidents.json"
    incidents = IncidentRegistry(incident_path)

    first = ContainmentService(incidents=incidents)
    first.register("agent-supplied")
    first.contain("agent-supplied")

    recovered = ContainmentService(incidents=IncidentRegistry(incident_path))
    executable_runtime = Runtime("agent-supplied")

    with pytest.raises(RuntimeError, match="durable containment state"):
        recovered.register(
            "agent-supplied",
            containment=ContainmentController(executable_runtime),
        )


def test_corrupt_incident_registry_fails_closed(tmp_path):
    incident_path = tmp_path / "incidents.json"
    incident_path.write_text("{corrupt", encoding="utf-8")

    with pytest.raises(RuntimeError, match="invalid incident registry"):
        ContainmentService(incidents=IncidentRegistry(incident_path))


def test_containment_survives_incident_persistence_failure(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    service.register("agent-storage")

    def fail_persist(_records=None):
        raise OSError("disk full")

    incidents._persist_locked = fail_persist
    report = service.contain("agent-storage")

    assert report.complete
    assert not report.durable
    assert report.persistence_failures
    assert service.status("agent-storage") is RuntimeState.CONTAINED
    assert service.incident("agent-storage") is None



def test_recovery_requires_controller_authorization_and_invalidates_stale_leases(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    runtime = service.register("agent-recover")
    old_lease = runtime.acquire_lease()
    assert old_lease is not None

    service.contain("agent-recover")
    authorization = service.issue_recovery_authorization("agent-recover")
    epoch = service.recover("agent-recover", authorization)

    assert epoch == 2
    assert runtime.state is RuntimeState.ACTIVE
    assert runtime.execute_if_active(old_lease, lambda: "stale") is None

    new_lease = runtime.acquire_lease()
    assert new_lease is not None
    assert runtime.execute_if_active(new_lease, lambda: "ok") == "ok"
    assert service.incident("agent-recover").state is IncidentState.RECOVERED


def test_stale_controller_recovery_authorization_is_rejected(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    first = ContainmentService(incidents=incidents)
    runtime = first.register("agent-controller")
    first.contain("agent-controller")
    stale = first.issue_recovery_authorization("agent-controller")

    second = ContainmentService(incidents=IncidentRegistry(incidents.path))
    second.register(
        "agent-controller",
        containment=ContainmentController(runtime),
    )

    with pytest.raises(PermissionError, match="stale"):
        second.recover("agent-controller", stale)

    fresh = second.issue_recovery_authorization("agent-controller")
    assert second.recover("agent-controller", fresh) == 2


def test_recovery_fails_closed_when_incident_persistence_is_unavailable(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    runtime = service.register("agent-recovery-storage")
    service.contain("agent-recovery-storage")
    authorization = service.issue_recovery_authorization("agent-recovery-storage")

    def fail_persist(_records=None):
        raise OSError("disk full")

    incidents._persist_locked = fail_persist

    with pytest.raises(OSError, match="disk full"):
        service.recover("agent-recovery-storage", authorization)

    assert runtime.state is RuntimeState.CONTAINED
    assert service.incident("agent-recovery-storage").state is IncidentState.CONTAINED


def test_recovered_incident_requires_explicit_runtime_after_restart(tmp_path):
    incident_path = tmp_path / "incidents.json"
    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    runtime = first.register("agent-restart-recovered")
    first.contain("agent-restart-recovered")
    authorization = first.issue_recovery_authorization("agent-restart-recovered")
    assert first.recover("agent-restart-recovered", authorization) == 2

    second = ContainmentService(incidents=IncidentRegistry(incident_path))
    with pytest.raises(RuntimeError, match="explicitly supplied active runtime"):
        second.register("agent-restart-recovered")

    supplied = Runtime("agent-restart-recovered")
    supplied._restore_active(2)
    restored = second.register(
        "agent-restart-recovered",
        containment=ContainmentController(supplied),
    )
    assert restored.state is RuntimeState.ACTIVE
    assert restored.epoch == 2


def test_containment_after_recovery_persistence_failure_fails_closed_on_restart(tmp_path):
    incident_path = tmp_path / "incidents.json"
    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    runtime = first.register("agent-recovery-contain-failure")
    first.contain("agent-recovery-contain-failure")
    authorization = first.issue_recovery_authorization("agent-recovery-contain-failure")
    assert first.recover("agent-recovery-contain-failure", authorization) == 2

    def fail_persist(_records=None):
        raise OSError("disk full")

    first.incidents._persist_locked = fail_persist
    report = first.contain("agent-recovery-contain-failure")

    assert report.complete
    assert not report.durable
    assert runtime.state is RuntimeState.CONTAINED
    assert first.incident("agent-recovery-contain-failure").state is IncidentState.RECOVERED

    restarted = ContainmentService(incidents=IncidentRegistry(incident_path))
    restored = restarted.register("agent-recovery-contain-failure")

    assert restored.state is RuntimeState.CONTAINED
    assert restored.epoch == 3
    assert restored.acquire_lease() is None



def test_recovery_authorization_is_invalid_after_controller_restart(tmp_path):
    incident_path = tmp_path / "incidents.json"
    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    runtime = first.register("agent-restart-auth")
    first.contain("agent-restart-auth")
    stale = first.issue_recovery_authorization("agent-restart-auth")

    second = ContainmentService(incidents=IncidentRegistry(incident_path))
    second.register(
        "agent-restart-auth",
        containment=ContainmentController(runtime),
    )

    with pytest.raises(PermissionError, match="stale"):
        second.recover("agent-restart-auth", stale)

    fresh = second.issue_recovery_authorization("agent-restart-auth")
    assert second.recover("agent-restart-auth", fresh) == 2
    assert runtime.state is RuntimeState.ACTIVE


def test_repeated_containment_recovery_cycles_advance_epochs_and_preserve_fencing(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    runtime = service.register("agent-lifecycle-cycles")

    for cycle in range(1, 6):
        expected_containment_epoch = (cycle * 2) - 1
        lease = runtime.acquire_lease()
        report = service.contain("agent-lifecycle-cycles")
        assert report.complete
        assert report.epoch == expected_containment_epoch
        assert runtime.state is RuntimeState.CONTAINED
        assert not runtime.lease_valid(lease)

        authorization = service.issue_recovery_authorization("agent-lifecycle-cycles")
        assert service.recover("agent-lifecycle-cycles", authorization) == expected_containment_epoch + 1
        assert runtime.state is RuntimeState.ACTIVE
        assert runtime.epoch == expected_containment_epoch + 1

        assert runtime.execute_if_active(lease, lambda: None) is None

    incident = service.incident("agent-lifecycle-cycles")
    assert incident is not None
    assert incident.state is IncidentState.RECOVERED
    assert incident.containment_epoch == 9
    assert incident.recovery_epoch == 10


def test_recovery_authorization_cannot_be_fabricated_with_wrong_capability(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    runtime = service.register("agent-fake")
    service.contain("agent-fake")
    authorization = service.issue_recovery_authorization("agent-fake")

    fake = type(authorization)(
        agent_id=authorization.agent_id,
        containment_epoch=authorization.containment_epoch,
        _capability=object(),
    )

    with pytest.raises(PermissionError, match="stale"):
        service.recover("agent-fake", fake)

    assert runtime.state is RuntimeState.CONTAINED


def test_proof_attachment_cannot_reopen_a_recovered_incident(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    service.register("agent-proof-after")
    service.contain("agent-proof-after")
    auth = service.issue_recovery_authorization("agent-proof-after")
    service.recover("agent-proof-after", auth)

    incident = service.incident("agent-proof-after")
    with pytest.raises(ValueError, match="after recovery"):
        incidents.attach_proof(incident.incident_id, "proof-1")



def test_containment_and_recovery_are_serialized(tmp_path):
    incidents = IncidentRegistry(tmp_path / "incidents.json")
    service = ContainmentService(incidents=incidents)
    runtime = service.register("agent-race-recovery")
    service.contain("agent-race-recovery")
    auth = service.issue_recovery_authorization("agent-race-recovery")

    import threading

    barrier = threading.Barrier(2, timeout=2)
    results = []

    def recover():
        barrier.wait()
        try:
            results.append(("recover", service.recover("agent-race-recovery", auth)))
        except Exception as exc:
            results.append(("recover-error", type(exc).__name__))

    def contain():
        barrier.wait()
        results.append(("contain", service.contain("agent-race-recovery").epoch))

    t1 = threading.Thread(target=recover)
    t2 = threading.Thread(target=contain)
    t1.start()
    t2.start()
    t1.join(timeout=2)
    t2.join(timeout=2)

    assert not t1.is_alive()
    assert not t2.is_alive()
    assert len(results) == 2
    assert runtime.state in (RuntimeState.ACTIVE, RuntimeState.CONTAINED)
    assert service.incident("agent-race-recovery") is not None



def test_recovery_authorization_is_invalid_after_new_containment():
    incidents = IncidentRegistry()
    service = ContainmentService(incidents=incidents)
    runtime = service.register("agent-stale-after-contain")
    service.contain("agent-stale-after-contain")
    auth = service.issue_recovery_authorization("agent-stale-after-contain")
    service.recover("agent-stale-after-contain", auth)

    service.contain("agent-stale-after-contain")

    try:
        service.recover("agent-stale-after-contain", auth)
    except PermissionError:
        pass
    else:
        raise AssertionError("stale recovery authorization was accepted")

    assert runtime.state is RuntimeState.CONTAINED
    incident = service.incident("agent-stale-after-contain")
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert incident.containment_epoch == runtime.epoch


def test_execute_if_active_cannot_start_after_containment_transition():
    runtime = Runtime("agent-execute-containment-race")
    lease = runtime.acquire_lease()
    assert lease is not None

    runtime.contain()
    started = []

    assert runtime.execute_if_active(
        lease,
        lambda: started.append(True),
    ) is None
    assert started == []
    assert runtime.state is RuntimeState.CONTAINED
