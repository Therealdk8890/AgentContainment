from agent_containment.credentials import CredentialStore


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
