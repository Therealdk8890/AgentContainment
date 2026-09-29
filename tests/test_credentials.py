from agent_containment.credentials import CredentialStore
from agent_containment.runtime import Runtime


def test_revocation_invalidates_existing_credential_lease():
    store = CredentialStore()
    lease = store.issue("aws-prod")

    assert store.valid(lease)

    store.revoke("aws-prod")

    assert not store.valid(lease)


def test_reissued_credential_gets_new_lease_epoch():
    store = CredentialStore()
    first = store.issue("database")

    store.revoke("database")
    second = store.issue("database")

    assert not store.valid(first)
    assert store.valid(second)


def test_revoke_all_invalidates_every_credential():
    store = CredentialStore()
    leases = [store.issue(name) for name in ("aws", "github", "database")]

    store.revoke_all()

    assert all(not store.valid(lease) for lease in leases)


def test_runtime_bound_credentials_follow_runtime_epoch():
    runtime = Runtime("agent-1")
    store = CredentialStore(runtime=runtime)

    first = store.issue("database")
    assert first.epoch == runtime.epoch
    assert store.valid(first)

    runtime.contain()
    assert runtime.epoch == first.epoch + 1
    assert not store.valid(first)

    try:
        store.issue("database")
    except RuntimeError as exc:
        assert "active runtime" in str(exc)
    else:
        raise AssertionError("contained runtime minted credential authority")

    recovered_epoch = runtime.recover(
        runtime._recovery_capability,
        expected_epoch=runtime.epoch,
    )
    second = store.issue("database")

    assert second.epoch == recovered_epoch
    assert second.epoch > first.epoch
    assert not store.valid(first)
    assert store.valid(second)


def test_runtime_bound_execution_cannot_cross_containment_boundary():
    runtime = Runtime("agent-2")
    store = CredentialStore(runtime=runtime)
    lease = store.issue("database")
    executed: list[str] = []

    assert store.execute_if_valid(
        lease,
        lambda: executed.append("before"),
    ) is None
    assert executed == ["before"]

    runtime.contain()

    assert store.execute_if_valid(
        lease,
        lambda: executed.append("after"),
    ) is None
    assert executed == ["before"]



def test_runtime_bound_issuance_is_atomic_with_concurrent_containment():
    from threading import Event, Thread

    runtime = Runtime("agent-race")
    store = CredentialStore(runtime=runtime)
    entered = Event()
    release = Event()
    contained = Event()
    issued: list[object] = []
    errors: list[Exception] = []

    original_issue_if_active = runtime.issue_if_active

    def gated_issue(issuer):
        def wrapped(runtime_lease):
            entered.set()
            assert release.wait(timeout=5)
            return issuer(runtime_lease)

        return original_issue_if_active(wrapped)

    runtime.issue_if_active = gated_issue

    def issue():
        try:
            issued.append(store.issue("prod-api"))
        except Exception as exc:
            errors.append(exc)

    def contain():
        runtime.contain()
        contained.set()

    issuer_thread = Thread(target=issue)
    issuer_thread.start()
    assert entered.wait(timeout=5)

    containment_thread = Thread(target=contain)
    containment_thread.start()

    # The issuer callback is executing while Runtime.issue_if_active holds the
    # runtime lock. Containment therefore cannot cross the authority boundary
    # until issuance has committed.
    assert not contained.wait(timeout=0.1)
    release.set()

    issuer_thread.join(timeout=5)
    containment_thread.join(timeout=5)

    assert not errors
    assert len(issued) == 1
    assert contained.is_set()
    assert runtime.state.value == "contained"
    assert not store.valid(issued[0])
