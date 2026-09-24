import pytest

from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.credentials import CredentialStore
from agent_containment.egress import EgressController
from agent_containment.models import Action, DecisionType
from agent_containment.runtime import Runtime, RuntimeState


def test_stale_execution_lease_cannot_run_after_containment():
    runtime = Runtime("escape-agent")
    lease = runtime.acquire_lease()

    assert lease is not None
    runtime.contain()

    executed = False

    def side_effect():
        nonlocal executed
        executed = True
        return "should-not-run"

    assert runtime.execute_if_active(lease, side_effect) is None
    assert executed is False
    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.lease_valid(lease) is False


def test_stale_egress_lease_cannot_authorize_after_containment():
    runtime = Runtime("escape-agent")
    egress = EgressController(runtime)
    lease = egress.acquire_lease()

    assert lease is not None
    runtime.contain()

    assert egress.authorize(lease) is False
    assert egress.lease_valid(lease) is False
    assert egress.acquire_lease() is None


def test_containment_revokes_credentials_and_capabilities():
    runtime = Runtime("escape-agent")
    credentials = CredentialStore()
    credential = credentials.issue("api-key")
    capabilities = CapabilitySet({"filesystem.write", "network.egress"})
    controller = ContainmentController(runtime, capabilities, credentials=credentials)

    assert credentials.valid(credential)
    report = controller.contain()

    assert report.complete
    assert runtime.state is RuntimeState.CONTAINED
    assert capabilities.capabilities == set()
    assert credentials.credentials == set()
    assert credentials.valid(credential) is False


def test_connection_cannot_be_registered_after_containment():
    runtime = Runtime("escape-agent")
    egress = EgressController(runtime)
    controller = ContainmentController(runtime)
    controller.attach_egress(egress)

    terminated = []

    assert egress.register_connection(
        "escape-agent", "conn-1", lambda: terminated.append("conn-1")
    )
    controller.contain()

    assert terminated == ["conn-1"]
    assert egress.active_connection_ids("escape-agent") == ()
    assert egress.register_connection(
        "escape-agent", "conn-2", lambda: terminated.append("conn-2")
    ) is False
    assert terminated == ["conn-1"]


def test_recovery_requires_current_controller_authorization():
    service = ContainmentService()
    runtime = service.register("escape-agent")
    service.contain("escape-agent")

    auth = service.issue_recovery_authorization("escape-agent")

    with pytest.raises(PermissionError):
        service.recover(
            "escape-agent",
            type(auth)(
                agent_id=auth.agent_id,
                containment_epoch=auth.containment_epoch,
                _capability=object(),
            ),
        )

    assert runtime.state is RuntimeState.CONTAINED


def test_recovery_authorization_cannot_be_reused():
    service = ContainmentService()
    runtime = service.register("escape-agent")
    service.contain("escape-agent")

    auth = service.issue_recovery_authorization("escape-agent")
    recovered_epoch = service.recover("escape-agent", auth)

    assert runtime.state is RuntimeState.ACTIVE

    with pytest.raises(PermissionError):
        service.recover("escape-agent", auth)

    assert runtime.epoch == recovered_epoch


def test_controller_fence_survives_enforcement_failure():
    class FailingEnforcer:
        def contain(self):
            raise RuntimeError("simulated enforcement failure")

    runtime = Runtime("escape-agent")
    controller = ContainmentController(
        runtime,
        CapabilitySet({"network.egress"}),
        kernel_egress=FailingEnforcer(),
    )

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert controller.capabilities.capabilities == set()
    assert not report.complete
    assert any("kernel_egress_contained" in failure for failure in report.failures)


def test_authorization_denies_non_executable_runtime():
    service = ContainmentService()
    runtime = service.register("escape-agent")
    service.contain("escape-agent")

    decision = service.authorize(
        Action("escape-agent", "post-containment", "write", "prod-db", risk=1)
    )

    assert decision.decision is DecisionType.DENY
    assert runtime.state is RuntimeState.CONTAINED
