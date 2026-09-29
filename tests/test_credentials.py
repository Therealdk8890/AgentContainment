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
