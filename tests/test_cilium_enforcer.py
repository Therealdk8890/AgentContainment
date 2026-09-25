import json
import subprocess

from agent_containment.cilium_enforcer import CiliumNetworkPolicyEnforcer
from agent_containment.enforcer import EnforcementStatus


class FakeKubectl:
    def __init__(self):
        self.policy = None
        self.calls = []

    def __call__(self, args, stdin=None):
        self.calls.append((list(args), stdin))
        if args[:1] == ["apply"]:
            self.policy = json.loads(stdin)
            return subprocess.CompletedProcess(args, 0, stdout="configured\n", stderr="")
        if args[:1] == ["get"]:
            if self.policy is None:
                return subprocess.CompletedProcess(
                    args, 1, stdout="", stderr="Error from server (NotFound): missing"
                )
            return subprocess.CompletedProcess(
                args, 0, stdout=json.dumps(self.policy), stderr=""
            )
        if args[:1] == ["delete"]:
            self.policy = None
            return subprocess.CompletedProcess(args, 0, stdout="deleted\n", stderr="")
        raise AssertionError(args)


def test_contain_creates_and_verifies_exact_policy():
    kubectl = FakeKubectl()
    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app.kubernetes.io/name": "agent-1"}},
        namespace="agents",
        kubectl=kubectl,
    )

    result = enforcer.contain("agent-1")

    assert result.status is EnforcementStatus.ENFORCED
    verification = enforcer.verify_contained("agent-1")
    assert verification.status is EnforcementStatus.ENFORCED

    manifest = kubectl.policy
    assert manifest["kind"] == "CiliumNetworkPolicy"
    assert manifest["metadata"]["namespace"] == "agents"
    assert manifest["spec"]["endpointSelector"]["matchLabels"] == {
        "app.kubernetes.io/name": "agent-1"
    }
    assert manifest["spec"]["ingressDeny"] == [{"fromEntities": ["all"]}]
    assert manifest["spec"]["egressDeny"] == [{"toEntities": ["all"]}]


def test_modified_policy_fails_verification():
    kubectl = FakeKubectl()
    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}}, kubectl=kubectl
    )

    assert enforcer.contain("agent-1").status is EnforcementStatus.ENFORCED
    kubectl.policy["spec"]["endpointSelector"]["matchLabels"]["app"] = "other"

    assert (
        enforcer.verify_contained("agent-1").status
        is EnforcementStatus.VERIFICATION_FAILED
    )


def test_release_requires_policy_to_disappear():
    kubectl = FakeKubectl()
    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}}, kubectl=kubectl
    )

    enforcer.contain("agent-1")
    assert enforcer.release("agent-1").status is EnforcementStatus.RELEASED
    assert enforcer.verify_released("agent-1").status is EnforcementStatus.RELEASED


def test_missing_policy_fails_containment_verification():
    kubectl = FakeKubectl()
    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}}, kubectl=kubectl
    )

    assert (
        enforcer.verify_contained("agent-1").status
        is EnforcementStatus.VERIFICATION_FAILED
    )


def test_unknown_agent_is_not_configured():
    enforcer = CiliumNetworkPolicyEnforcer({})

    assert enforcer.contain("missing").status is EnforcementStatus.NOT_CONFIGURED


def test_apply_failure_is_degraded():
    def failed(args, stdin=None):
        return subprocess.CompletedProcess(
            args, 1, stdout="", stderr="forbidden"
        )

    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}}, kubectl=failed
    )

    result = enforcer.contain("agent-1")

    assert result.status is EnforcementStatus.DEGRADED
    assert "forbidden" in result.detail
