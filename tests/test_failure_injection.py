import pytest

from agent_containment.containment import CapabilitySet, ContainmentController
from agent_containment.credentials import CredentialStore
from agent_containment.egress import EgressController
from agent_containment.runtime import Runtime, RuntimeState


class Failing:
    def __init__(self, message="injected failure"):
        self.message = message
        self.calls = 0

    def contain(self):
        self.calls += 1
        raise RuntimeError(self.message)


def test_kernel_enforcement_failure_keeps_runtime_contained():
    runtime = Runtime("failure-agent")
    controller = ContainmentController(
        runtime,
        CapabilitySet({"network.egress"}),
        kernel_egress=Failing("kernel failure"),
    )

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert controller.capabilities.capabilities == set()
    assert report.complete is False


def test_multiple_contain_calls_remain_fail_closed():
    runtime = Runtime("failure-agent")
    failing = Failing()
    controller = ContainmentController(
        runtime,
        CapabilitySet({"network.egress"}),
        kernel_egress=failing,
    )

    first = controller.contain()
    second = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert first.complete is False
    assert second.complete is False
    assert failing.calls >= 1


def test_egress_enforcement_failure_does_not_reopen_network():
    runtime = Runtime("failure-agent")
    egress = EgressController(runtime)
    controller = ContainmentController(
        runtime,
        CapabilitySet({"network.egress"}),
        kernel_egress=Failing("egress failure"),
    )
    controller.attach_egress(egress)

    lease = egress.acquire_lease()
    assert lease is not None

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert egress.authorize(lease) is False
    assert egress.acquire_lease() is None
    assert report.complete is False


def test_credential_revocation_failure_cannot_restore_execution():
    class FailingCredentials(CredentialStore):
        def revoke_all(self):
            raise RuntimeError("credential store unavailable")

    runtime = Runtime("failure-agent")
    credentials = FailingCredentials()
    capabilities = CapabilitySet({"filesystem.write"})
    controller = ContainmentController(
        runtime,
        capabilities,
        credentials=credentials,
    )

    report = controller.contain()

    assert runtime.state is RuntimeState.CONTAINED
    assert capabilities.capabilities == set()
    assert report.complete is False


def test_failed_enforcement_never_transitions_runtime_back_to_active():
    runtime = Runtime("failure-agent")
    controller = ContainmentController(
        runtime,
        CapabilitySet({"network.egress", "filesystem.write"}),
        kernel_egress=Failing("controller unavailable"),
    )

    controller.contain()

    with pytest.raises(PermissionError):
        runtime.recover()

    assert runtime.state is RuntimeState.CONTAINED
