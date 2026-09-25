"""Cilium NetworkPolicy enforcement adapter.

This module deliberately uses the kubectl CLI instead of adding a Kubernetes
client dependency to the core library. The controller owns the containment
decision; Cilium owns the network enforcement datapath.

The adapter creates a namespace-scoped CiliumNetworkPolicy selecting exactly
the configured workload labels and denying ingress and egress. Verification
checks the live Kubernetes object and its selector/rules, so an acknowledged
apply is not treated as proof of enforcement.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
from dataclasses import dataclass
from typing import Callable, Mapping, Protocol, Sequence

from .enforcer import EnforcementResult, EnforcementStatus


class _CommandRunner(Protocol):
    def __call__(
        self, args: Sequence[str], stdin: str | None = None
    ) -> subprocess.CompletedProcess[str]:
        ...


def _kubectl_runner(
    args: Sequence[str], stdin: str | None = None
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["kubectl", *args],
        input=stdin,
        text=True,
        capture_output=True,
        check=False,
    )


@dataclass(frozen=True)
class CiliumPolicyIdentity:
    """Stable Cilium policy name and workload selector for one agent."""

    name: str
    selector: Mapping[str, str]


class CiliumNetworkPolicyEnforcer:
    """Contain workloads by installing a deny-all CiliumNetworkPolicy.

    The workload must already carry the configured Kubernetes labels. The
    adapter never mutates workload labels and therefore cannot accidentally
    select an unrelated workload because of a generated label.

    This is intentionally a network-containment adapter: it does not replace
    process containment, credential revocation, or the controller's durable
    runtime fence.
    """

    name = "cilium-network-policy"

    def __init__(
        self,
        selectors: Mapping[str, Mapping[str, str]],
        *,
        namespace: str = "default",
        kubectl: _CommandRunner = _kubectl_runner,
        datapath_verifier: Callable[[CiliumPolicyIdentity], EnforcementResult] | None = None,
    ):
        if not namespace or namespace.startswith("-"):
            raise ValueError("namespace must be a non-empty Kubernetes namespace")
        self._namespace = namespace
        self._kubectl = kubectl
        self._datapath_verifier = datapath_verifier or self._verify_cilium_endpoint_datapath
        self._identities: dict[str, CiliumPolicyIdentity] = {}

        for agent_id, selector in selectors.items():
            if not agent_id:
                raise ValueError("agent_id must be non-empty")
            if not selector or any(not key or not value for key, value in selector.items()):
                raise ValueError(f"selector for {agent_id!r} must contain non-empty labels")
            digest = hashlib.sha256(agent_id.encode("utf-8")).hexdigest()[:20]
            self._identities[agent_id] = CiliumPolicyIdentity(
                name=f"agentcontainment-{digest}",
                selector=dict(selector),
            )

    def _identity(self, agent_id: str) -> CiliumPolicyIdentity | None:
        return self._identities.get(agent_id)

    def _missing(self, agent_id: str) -> EnforcementResult:
        return EnforcementResult(
            self.name,
            EnforcementStatus.NOT_CONFIGURED,
            f"no Cilium selector configured for agent {agent_id}",
        )

    def _manifest(self, identity: CiliumPolicyIdentity) -> dict:
        return {
            "apiVersion": "cilium.io/v2",
            "kind": "CiliumNetworkPolicy",
            "metadata": {
                "name": identity.name,
                "namespace": self._namespace,
                "labels": {
                    "app.kubernetes.io/managed-by": "agentcontainment",
                    "agentcontainment.io/policy": "containment",
                },
            },
            "spec": {
                "description": (
                    "AgentContainment emergency network containment; "
                    "controller-owned and fail-closed."
                ),
                "endpointSelector": {"matchLabels": dict(identity.selector)},
                "ingressDeny": [{"fromEntities": ["all"]}],
                "egressDeny": [{"toEntities": ["all"]}],
            },
        }

    def _get(self, identity: CiliumPolicyIdentity) -> tuple[dict | None, str | None]:
        result = self._kubectl(
            [
                "get",
                "ciliumnetworkpolicy",
                identity.name,
                "-n",
                self._namespace,
                "-o",
                "json",
            ]
        )
        if result.returncode != 0:
            stderr = (result.stderr or "").strip()
            if "NotFound" in stderr or "not found" in stderr.lower():
                return None, None
            return None, stderr or f"kubectl exited {result.returncode}"
        try:
            return json.loads(result.stdout), None
        except json.JSONDecodeError as exc:
            return None, f"invalid kubectl JSON response: {exc}"

    def _matches_containment_policy(
        self, identity: CiliumPolicyIdentity, obj: Mapping[str, object]
    ) -> bool:
        metadata = obj.get("metadata")
        spec = obj.get("spec")
        if not isinstance(metadata, Mapping) or not isinstance(spec, Mapping):
            return False
        if metadata.get("name") != identity.name or metadata.get("namespace") != self._namespace:
            return False
        labels = metadata.get("labels")
        if not isinstance(labels, Mapping):
            return False
        if labels.get("app.kubernetes.io/managed-by") != "agentcontainment":
            return False
        if labels.get("agentcontainment.io/policy") != "containment":
            return False

        selector = spec.get("endpointSelector")
        if not isinstance(selector, Mapping):
            return False
        if selector.get("matchLabels") != dict(identity.selector):
            return False

        ingress_deny = spec.get("ingressDeny")
        egress_deny = spec.get("egressDeny")
        return (
            ingress_deny == [{"fromEntities": ["all"]}]
            and egress_deny == [{"toEntities": ["all"]}]
        )

    def _verify_cilium_endpoint_datapath(
        self, identity: CiliumPolicyIdentity
    ) -> EnforcementResult:
        """Verify selected Cilium endpoints report both directions enforced."""
        selector = ",".join(
            f"{key}={value}" for key, value in sorted(identity.selector.items())
        )
        result = self._kubectl(
            [
                "get", "ciliumendpoints", "-n", self._namespace,
                "-l", selector, "-o", "json",
            ]
        )
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "").strip()
            return EnforcementResult(
                self.name, EnforcementStatus.VERIFICATION_FAILED,
                detail or f"kubectl get ciliumendpoints exited {result.returncode}",
            )
        try:
            payload = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.VERIFICATION_FAILED,
                f"invalid CiliumEndpoint JSON response: {exc}",
            )

        items = payload.get("items")
        if not isinstance(items, list) or not items:
            return EnforcementResult(
                self.name, EnforcementStatus.VERIFICATION_FAILED,
                "no CiliumEndpoint matched the containment selector",
            )

        for endpoint in items:
            status = endpoint.get("status") if isinstance(endpoint, Mapping) else None
            policy = status.get("policy") if isinstance(status, Mapping) else None
            realized = policy.get("realized") if isinstance(policy, Mapping) else None
            if not isinstance(realized, Mapping):
                return EnforcementResult(
                    self.name, EnforcementStatus.VERIFICATION_FAILED,
                    "CiliumEndpoint has no realized policy status",
                )
            if realized.get("policy-enabled") != "both":
                return EnforcementResult(
                    self.name, EnforcementStatus.VERIFICATION_FAILED,
                    "CiliumEndpoint policy enforcement is not enabled for both ingress and egress",
                )

        return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

    def contain(self, agent_id: str) -> EnforcementResult:
        identity = self._identity(agent_id)
        if identity is None:
            return self._missing(agent_id)
        try:
            manifest = json.dumps(self._manifest(identity), separators=(",", ":"))
            result = self._kubectl(
                ["apply", "--server-side", "--field-manager=agentcontainment", "-f", "-"],
                stdin=manifest,
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.DEGRADED,
                    detail or f"kubectl apply exited {result.returncode}",
                )
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)
        except (OSError, subprocess.SubprocessError) as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, f"{type(exc).__name__}: {exc}"
            )

    def verify_contained(self, agent_id: str) -> EnforcementResult:
        identity = self._identity(agent_id)
        if identity is None:
            return self._missing(agent_id)
        try:
            obj, error = self._get(identity)
            if error:
                return EnforcementResult(
                    self.name, EnforcementStatus.VERIFICATION_FAILED, error
                )
            if obj is None:
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.VERIFICATION_FAILED,
                    "containment policy is absent",
                )
            if not self._matches_containment_policy(identity, obj):
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.VERIFICATION_FAILED,
                    "live CiliumNetworkPolicy does not match the expected containment policy",
                )
            if self._datapath_verifier is not None:
                datapath = self._datapath_verifier(identity)
                if datapath.status is not EnforcementStatus.ENFORCED:
                    return EnforcementResult(
                        self.name,
                        EnforcementStatus.VERIFICATION_FAILED,
                        "Cilium policy object is present but datapath verification failed"
                        + (f": {datapath.detail}" if datapath.detail else ""),
                    )
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)
        except (OSError, subprocess.SubprocessError) as exc:
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                f"{type(exc).__name__}: {exc}",
            )

    def release(self, agent_id: str) -> EnforcementResult:
        identity = self._identity(agent_id)
        if identity is None:
            return self._missing(agent_id)
        try:
            result = self._kubectl(
                [
                    "delete",
                    "ciliumnetworkpolicy",
                    identity.name,
                    "-n",
                    self._namespace,
                    "--ignore-not-found=true",
                ]
            )
            if result.returncode != 0:
                detail = (result.stderr or result.stdout or "").strip()
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.DEGRADED,
                    detail or f"kubectl delete exited {result.returncode}",
                )
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)
        except (OSError, subprocess.SubprocessError) as exc:
            return EnforcementResult(
                self.name, EnforcementStatus.DEGRADED, f"{type(exc).__name__}: {exc}"
            )

    def verify_released(self, agent_id: str) -> EnforcementResult:
        identity = self._identity(agent_id)
        if identity is None:
            return self._missing(agent_id)
        try:
            obj, error = self._get(identity)
            if error:
                return EnforcementResult(
                    self.name, EnforcementStatus.VERIFICATION_FAILED, error
                )
            if obj is not None:
                return EnforcementResult(
                    self.name,
                    EnforcementStatus.VERIFICATION_FAILED,
                    "containment policy is still present",
                )
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)
        except (OSError, subprocess.SubprocessError) as exc:
            return EnforcementResult(
                self.name,
                EnforcementStatus.VERIFICATION_FAILED,
                f"{type(exc).__name__}: {exc}",
            )
