from agent_containment.proof import record_proof
from agent_containment.runtime import Runtime, RuntimeState


def test_stale_execution_lease_cannot_cross_containment_or_recovery():
    """An agent must not regain authority from a lease issued in an old epoch."""
    runtime = Runtime("agent-1")

    epoch_zero_lease = runtime.acquire_lease()
    assert epoch_zero_lease is not None
    assert epoch_zero_lease.epoch == 0
    assert runtime.lease_valid(epoch_zero_lease)

    executed: list[str] = []
    assert runtime.execute_if_active(epoch_zero_lease, lambda: executed.append("before")) is None
    assert executed == ["before"]

    runtime.contain()
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1

    # The original authority is stale immediately after fencing.
    assert not runtime.lease_valid(epoch_zero_lease)
    assert runtime.execute_if_active(epoch_zero_lease, lambda: executed.append("stale-after-contain")) is None
    assert executed == ["before"]

    capability = runtime._rotate_recovery_capability()
    assert runtime.recover(capability, expected_epoch=1) == 2
    assert runtime.state is RuntimeState.ACTIVE

    # Recovery creates a fresh epoch; neither pre-containment lease nor an
    # inferred epoch-1 lease may authorize execution after recovery.
    assert not runtime.lease_valid(epoch_zero_lease)
    epoch_one_lease = type(epoch_zero_lease)("agent-1", 1)
    assert not runtime.lease_valid(epoch_one_lease)
    assert runtime.execute_if_active(epoch_zero_lease, lambda: executed.append("stale-after-recovery")) is None
    assert runtime.execute_if_active(epoch_one_lease, lambda: executed.append("epoch-one-after-recovery")) is None

    fresh_lease = runtime.acquire_lease()
    assert fresh_lease is not None
    assert fresh_lease.epoch == 2
    assert runtime.lease_valid(fresh_lease)
    assert runtime.execute_if_active(fresh_lease, lambda: executed.append("fresh")) is None
    assert executed == ["before", "fresh"]
    record_proof("stale_execution_lease")


def test_stale_lease_cannot_execute_during_containment_transition():
    """The atomic execution gate must reject a lease once fencing wins the lock."""
    runtime = Runtime("agent-2")
    lease = runtime.acquire_lease()
    assert lease is not None

    runtime.contain()

    side_effects: list[str] = []
    assert runtime.execute_if_active(lease, lambda: side_effects.append("executed")) is None
    assert side_effects == []
    assert runtime.state is RuntimeState.CONTAINED


def test_recovery_rejects_wrong_epoch_and_capability():
    runtime = Runtime("agent-3")
    runtime.contain()

    wrong_capability = object()
    try:
        runtime.recover(wrong_capability, expected_epoch=runtime.epoch)
    except PermissionError:
        pass
    else:
        raise AssertionError("untrusted recovery capability was accepted")

    capability = runtime._rotate_recovery_capability()
    try:
        runtime.recover(capability, expected_epoch=runtime.epoch - 1)
    except RuntimeError:
        pass
    else:
        raise AssertionError("stale recovery epoch was accepted")
