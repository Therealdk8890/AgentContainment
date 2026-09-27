import threading

from agent_containment.containment import ContainmentController
from agent_containment.credentials import CredentialStore
from agent_containment.runtime import Runtime, RuntimeState


THREAD_TIMEOUT = 2


class FailingCredentialStore(CredentialStore):
    def revoke_all(self) -> None:
        raise RuntimeError("credential backend unavailable")


def test_credential_lease_is_invalid_after_containment():
    runtime = Runtime("agent-1")
    credentials = CredentialStore()
    lease = credentials.issue("prod-api")
    controller = ContainmentController(runtime, credentials=credentials)

    report = controller.contain()

    assert "credentials_revoked" in report.stages
    assert not credentials.valid(lease)
    assert runtime.state is RuntimeState.CONTAINED


def test_credential_failure_cannot_uncontain_runtime():
    runtime = Runtime("agent-1")
    controller = ContainmentController(
        runtime,
        credentials=FailingCredentialStore(),
    )

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert not report.complete
    assert any("credentials_revoked" in failure for failure in report.failures)


def test_containment_revokes_multiple_credentials():
    runtime = Runtime("agent-1")
    credentials = CredentialStore()
    leases = [credentials.issue(name) for name in ("aws", "github", "db")]
    controller = ContainmentController(runtime, credentials=credentials)

    controller.contain()

    assert all(not credentials.valid(lease) for lease in leases)


def test_concurrent_revoke_race_invalidates_lease():
    runtime = Runtime("agent-1")
    credentials = CredentialStore()
    lease = credentials.issue("prod-api")
    controller = ContainmentController(runtime, credentials=credentials)
    barrier = threading.Barrier(2, timeout=THREAD_TIMEOUT)
    observed = []

    def contain():
        barrier.wait()
        controller.contain()

    def use_lease():
        barrier.wait()
        observed.append(credentials.valid(lease))

    t1 = threading.Thread(target=contain)
    t2 = threading.Thread(target=use_lease)
    t1.start()
    t2.start()
    t1.join(timeout=THREAD_TIMEOUT)
    t2.join(timeout=THREAD_TIMEOUT)

    assert not t1.is_alive()
    assert not t2.is_alive()
    assert runtime.state is RuntimeState.CONTAINED
    assert not credentials.valid(lease)
    assert observed in ([True], [False])


def test_credential_use_is_atomic_with_revoke():
    runtime = Runtime("agent-1")
    credentials = CredentialStore()
    lease = credentials.issue("prod-api")
    controller = ContainmentController(runtime, credentials=credentials)

    entered = threading.Event()
    release = threading.Event()
    executed = []

    def use_credential():
        def executor():
            entered.set()
            assert release.wait(timeout=THREAD_TIMEOUT)
            executed.append("used")
            return "ok"

        result = credentials.execute_if_valid(lease, executor)
        assert result == "ok"

    use_thread = threading.Thread(target=use_credential)
    use_thread.start()
    assert entered.wait(timeout=THREAD_TIMEOUT)

    contain_thread = threading.Thread(target=controller.contain)
    contain_thread.start()

    # Revocation must wait for the credential-use boundary to finish.
    release.set()
    use_thread.join(timeout=THREAD_TIMEOUT)
    contain_thread.join(timeout=THREAD_TIMEOUT)

    assert not use_thread.is_alive()
    assert not contain_thread.is_alive()
    assert executed == ["used"]
    assert not credentials.valid(lease)
    assert runtime.state is RuntimeState.CONTAINED


def test_stale_credential_use_is_rejected_without_side_effect():
    runtime = Runtime("agent-1")
    credentials = CredentialStore()
    lease = credentials.issue("prod-api")
    controller = ContainmentController(runtime, credentials=credentials)

    controller.contain()
    executed = []

    assert credentials.execute_if_valid(
        lease,
        lambda: executed.append("used"),
    ) is None
    assert executed == []
