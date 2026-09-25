import json
import subprocess

from agent_containment.cilium_enforcer import CiliumNetworkPolicyEnforcer
from agent_containment.enforcer import EnforcementResult, EnforcementStatus


class FakeKubectl:
    def __init__(self):
        self.policy = None
        self.calls = []

    def __call__(self, args, stdin=None):
        self.calls.append((list(args), stdin))
        if args[:1] == ["apply"]:
            self.policy = json.loads(stdin)
            return subprocess.CompletedProcess(args, 0, stdout="configured\n", stderr="")
        if args[:2] == ["get", "ciliumendpoints"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=json.dumps(
                    {
                        "items": [
                            {
                                "status": {
                                    "policy": {
                                        "realized": {"policy-enabled": "both"}
                                    }
                                }
                            }
                        ]
                    }
                ),
                stderr="",
            )
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


def test_custom_datapath_verifier_can_certify_realized_enforcement():
    kubectl = FakeKubectl()
    calls = []

    def verifier(identity):
        calls.append(identity.name)
        return EnforcementResult(
            "datapath", EnforcementStatus.ENFORCED
        )

    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}},
        kubectl=kubectl,
        datapath_verifier=verifier,
    )

    enforcer.contain("agent-1")
    assert enforcer.verify_contained("agent-1").status is EnforcementStatus.ENFORCED
    assert calls == [enforcer._identities["agent-1"].name]


def test_custom_datapath_verifier_failure_does_not_certify_policy():
    kubectl = FakeKubectl()

    def verifier(identity):
        return EnforcementResult(
            "datapath",
            EnforcementStatus.VERIFICATION_FAILED,
            "endpoint policy not realized",
        )

    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}},
        kubectl=kubectl,
        datapath_verifier=verifier,
    )

    enforcer.contain("agent-1")
    result = enforcer.verify_contained("agent-1")
    assert result.status is EnforcementStatus.VERIFICATION_FAILED
    assert "endpoint policy not realized" in result.detail


def test_cilium_endpoint_realization_failure_blocks_certification():
    kubectl = FakeKubectl()

    original = kubectl.__call__

    def endpoint_not_ready(args, stdin=None):
        if args[:2] == ["get", "ciliumendpoints"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=json.dumps(
                    {
                        "items": [
                            {
                                "status": {
                                    "policy": {
                                        "realized": {"policy-enabled": "egress"}
                                    }
                                }
                            }
                        ]
                    }
                ),
                stderr="",
            )
        return original(args, stdin)

    enforcer = CiliumNetworkPolicyEnforcer(
        {"agent-1": {"app": "agent-1"}}, kubectl=endpoint_not_ready
    )
    enforcer.contain("agent-1")
    result = enforcer.verify_contained("agent-1")
    assert result.status is EnforcementStatus.VERIFICATION_FAILED
    assert "both ingress and egress" in result.detail
