from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.runtime import Runtime, RuntimeState


def test_controller_owns_containment_authority():
    service = ContainmentService()
    runtime = service.register("agent-1", metadata={"owner": "test"})
    assert service.status("agent-1") is RuntimeState.ACTIVE
    assert runtime.can_execute
    report = service.contain("agent-1")
    assert report.complete
    assert service.status("agent-1") is RuntimeState.CONTAINED
    assert not runtime.can_execute


def test_controller_can_manage_preconfigured_enforcement():
    service = ContainmentService()
    runtime = Runtime("agent-2")
    controller = ContainmentController(runtime, CapabilitySet({"network"}))
    service.register("agent-2", containment=controller)
    report = service.contain("agent-2")
    assert report.complete
    assert controller.capabilities.capabilities == set()


def test_duplicate_registration_is_rejected():
    service = ContainmentService()
    service.register("agent-1")
    try:
        service.register("agent-1")
    except ValueError as exc:
        assert "already registered" in str(exc)
    else:
        raise AssertionError("duplicate registration must fail")
