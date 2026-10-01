import hashlib
import json

from agent_containment.runtime import Runtime, RuntimeState
from agent_containment.runtime_observation import RuntimeObservationSource


def test_runtime_snapshot_is_atomic_and_epoch_bound():
    runtime = Runtime("agent-1")

    before = runtime.snapshot()
    assert before.agent_id == "agent-1"
    assert before.epoch == 0
    assert before.state is RuntimeState.ACTIVE
    assert before.can_execute is True

    runtime.contain()

    after = runtime.snapshot()
    assert after.epoch == 1
    assert after.state is RuntimeState.CONTAINED
    assert after.can_execute is False


def test_runtime_observation_is_independently_derived_and_integrity_checked():
    runtime = Runtime("agent-2")
    source = RuntimeObservationSource()

    observation = source.observe(runtime)

    assert observation.schema == "agent-containment/runtime-observation/v1"
    assert observation.agent_id == "agent-2"
    assert observation.epoch == 0
    assert observation.state == "active"
    assert observation.can_execute is True
    assert observation.verify_integrity()
    assert source.matches(observation, runtime)


def test_stale_runtime_observation_cannot_be_reused_after_containment():
    runtime = Runtime("agent-3")
    source = RuntimeObservationSource()

    active_observation = source.observe(runtime)
    runtime.contain()

    contained_observation = source.observe(runtime)

    assert active_observation.epoch == 0
    assert contained_observation.epoch == 1
    assert not source.matches(active_observation, runtime)
    assert source.matches(contained_observation, runtime)


def test_tampered_runtime_observation_is_rejected():
    runtime = Runtime("agent-4")
    source = RuntimeObservationSource()
    observation = source.observe(runtime)

    payload = observation.to_dict()
    payload["epoch"] = 99

    tampered = type(observation)(
        schema=payload["schema"],
        runtime_id=payload["runtime_id"],
        agent_id=payload["agent_id"],
        epoch=payload["epoch"],
        state=payload["state"],
        can_execute=payload["can_execute"],
        observed_at=payload["observed_at"],
        digest=payload["digest"],
    )

    assert not tampered.verify_integrity()
    assert not source.matches(tampered, runtime)


def test_runtime_observation_digest_is_canonical():
    runtime = Runtime("agent-5")
    source = RuntimeObservationSource()
    observation = source.observe(runtime)

    payload = observation.payload()
    expected = hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ).hexdigest()

    assert observation.digest == expected
