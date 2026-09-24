import pytest

from agent_containment.control import ContainmentService
from agent_containment.containment import ContainmentController
from agent_containment.incident_state import IncidentRegistry, IncidentState
from agent_containment.runtime import Runtime, RuntimeState


def test_restart_rebuilds_contained_runtime_from_durable_incident(tmp_path):
    incident_path = tmp_path / "incidents.json"

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register("agent-fresh-runtime")
    first.contain("agent-fresh-runtime")

    restarted = ContainmentService(incidents=IncidentRegistry(incident_path))
    runtime = restarted.register("agent-fresh-runtime")

    assert runtime is not first._managed("agent-fresh-runtime").runtime
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    assert runtime.acquire_lease() is None

    auth = restarted.issue_recovery_authorization("agent-fresh-runtime")
    assert restarted.recover("agent-fresh-runtime", auth) == 2
    assert runtime.state is RuntimeState.ACTIVE


def test_restart_requires_new_controller_capability_for_recovery(tmp_path):
    incident_path = tmp_path / "incidents.json"

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register("agent-new-capability")
    first.contain("agent-new-capability")
    stale = first.issue_recovery_authorization("agent-new-capability")

    restarted = ContainmentService(incidents=IncidentRegistry(incident_path))
    runtime = restarted.register("agent-new-capability")

    with pytest.raises(PermissionError, match="stale"):
        restarted.recover("agent-new-capability", stale)

    assert runtime.state is RuntimeState.CONTAINED
    fresh = restarted.issue_recovery_authorization("agent-new-capability")
    assert restarted.recover("agent-new-capability", fresh) == 2


def test_restart_never_treats_contained_incident_as_recovered(tmp_path):
    incident_path = tmp_path / "incidents.json"

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register("agent-not-recovered")
    first.contain("agent-not-recovered")

    restarted = ContainmentService(incidents=IncidentRegistry(incident_path))
    runtime = restarted.register("agent-not-recovered")
    incident = restarted.incident("agent-not-recovered")

    assert runtime.state is RuntimeState.CONTAINED
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert incident.recovery_epoch is None
