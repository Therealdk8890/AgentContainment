# AgentContainment

**Control and enforcement layer for an AI agent governance stack.**

AgentContainment provides the control side of a broader agent-governance loop: authorize actions, detect policy violations, halt compromised runs, revoke authority, contain blast radius, verify external enforcement, and preserve verifiable incident evidence.

Paired with provenance and claim-verification layers such as DProvenanceKit and ClaimProofKit, it forms a closed governance loop:

`Observe → Prove → Authorize → Enforce → Contain → Recover → Regression`

The architectural goal is not a collection of unrelated security libraries. It is a composable governance stack in which DProvenanceKit explains **what happened**, AgentContainment enforces **what was allowed**, ClaimProofKit verifies **what is supported by evidence**, and incidents become durable inputs to **future regression tests**. It is intentionally provider-neutral: platform enforcement can be supplied by cgroup v2/eBPF, Cilium, Tetragon, or another independently verifiable enforcement system.

**Keywords:** AI agent security, agent containment, autonomous agent security, AI runtime security, agent security control plane, AI agent firewall, agent firewall, AI agent sandbox, agent sandboxing, AI guardrails, agent governance, AI safety, runtime enforcement, action authorization, policy enforcement, kill switch, incident response, blast radius containment, enforcement verification, Cilium, CiliumNetworkPolicy, Kubernetes network policy, Tetragon, eBPF, Linux cgroups, cgroup v2, zero trust, defense in depth, tamper-evident audit, security engineering, open source AI security.

## Governance stack

```text
                    AI GOVERNANCE STACK
                           |
              +------------+------------+
              |                         |
        PROVENANCE / PROOF        CONTROL / ENFORCEMENT
        DProvenanceKit            AgentContainment
              |                         |
        What happened?             What is allowed?
        Evidence                   Halt / revoke
        Regression                 Contain / recover
              |                         |
              +------------+------------+
                           |
                    GOVERNANCE LOOP
                           |
                 Incident → Evidence
                           |
                    Regression gate
```

The integration point is intentional:

- **Provenance** records the action, decision, evidence, and resulting incident state.
- **Containment** can consume provenance-linked incident context while retaining independent authority to halt the runtime.
- **Recovery** remains controller-authorized rather than agent-authorized.
- **Incidents** can be converted into deterministic regression cases so a previously observed failure becomes a future release gate.

See [`docs/GOVERNANCE_PLATFORM.md`](docs/GOVERNANCE_PLATFORM.md) for the platform architecture and implementation roadmap.

### Governance integration contract

The open-source stack is intentionally modular:

```text
             GOVERNANCE CONTRACT
                    │
        +-----------+-----------+
        ▼           ▼           ▼
 DProvenanceKit  AgentContainment  ClaimProofKit
    PROVE           CONTROL          VERIFY
        \             │             /
         \            │            /
          +------ regression ------+
```

AgentContainment emits controller-owned `GovernanceEvent` records and can
export incidents as `RegressionFixture` cases. Downstream provenance and
claim-verification systems can attach evidence and support decisions without
becoming the containment or recovery authority.

## Core model

`Detect → Prove → Halt → Contain → Map → Recover`

The containment plane is designed to sit **outside the agent's trust boundary**. An agent must not control its own kill switch, containment policy, credentials, or incident evidence.

## Why AgentContainment

Traditional agent guardrails often operate inside the application or framework executing the agent. AgentContainment is designed around a different security boundary:

> **The agent requests an action. The controller decides whether it is allowed. The enforcement layer can then stop the runtime and its network egress independently of the agent.**

This separation is intended to remain useful when an agent is compromised, misbehaving, or attempting to bypass its normal tool wrapper.

### cgroup v2 provider

The optional `CgroupV2Enforcer` adapts a dedicated Linux cgroup v2 workload boundary to the provider-neutral enforcement interface. It uses `cgroup.kill` for containment and verifies state through `cgroup.events`. Configured cgroups are identity-bound using filesystem metadata so a deleted-and-recreated path is not silently accepted as the original workload boundary. An empty cgroup is treated as evidence that the current workload has exited; the AgentContainment durable admission fence remains the controller-owned authority that prevents recovery without explicit authorization.

This adapter is a Linux enforcement integration, not a claim that the Python control plane alone provides kernel-level isolation. Production deployments should provision and protect the cgroup hierarchy outside the agent trust boundary and validate the privileged integration on the target host.

### Cilium provider

The optional `CiliumNetworkPolicyEnforcer` integrates the same provider contract with Kubernetes/Cilium. It creates a namespace-scoped `CiliumNetworkPolicy` for the configured workload selector and denies ingress and egress. It does not add a Kubernetes client dependency to the core library; the adapter invokes `kubectl` without a shell and verifies the live policy object before reporting containment. Release deletes the policy and verifies that it is absent. The enforcer also queries matching `CiliumEndpoint` resources and requires realized policy enforcement for both ingress and egress before certifying containment. A Kubernetes policy object alone is therefore not treated as sufficient proof of enforcement. Production deployments should still pair this with Cilium health checks and an independent process-containment mechanism.

## Enforcement layers

AgentContainment uses defense in depth:

1. **Action authorization** — deterministic policy decisions before tool execution.
2. **Stateful policy** — controller-owned action history can detect sequences where individually permitted actions become dangerous collectively.
3. **Epoch fencing** — containment invalidates outstanding execution and egress leases.
4. **Capability revocation** — application-level authority is revoked during containment.
5. **Process containment** — Linux cgroup v2 can terminate the contained cgroup with `cgroup.kill`.
6. **Kernel egress enforcement** — the Linux eBPF integration can attach a cgroup egress program that drops outbound packets.
7. **Tamper-evident evidence** — controller-owned audit events are recorded in a hash chain.

No single layer is treated as sufficient.

## Provider-neutral enforcement architecture

AgentContainment owns the **containment decision, durable admission fence, recovery authority, and enforcement verification state**. It does not require a particular kernel or network security product.

The enforcement boundary is intentionally pluggable:

```text
                    AgentContainment
             control plane / recovery authority
                          |
                 containment decision
                          v
              +-----------+-----------+
              |           |           |
           Cilium      Tetragon    cgroup/eBPF
           network      runtime       process/
          enforcement  enforcement    egress
              |           |           |
              +-----------+-----------+
                          v
                    OS / network
                          |
                          v
                     Verification
```

The controller follows:

```text
REQUEST CONTAINMENT → ENFORCE → VERIFY → CERTIFY CONTAINED
```

A provider is not considered successfully enforced merely because a command or API request was accepted. Providers return an explicit status such as `ENFORCED`, `VERIFICATION_FAILED`, `DEGRADED`, or `NOT_CONFIGURED`.

Cilium and Tetragon are **optional integration targets, not dependencies of the core library**. AgentContainment is not intended to replace either project's kernel-level enforcement or telemetry capabilities. Its role is to provide an agent-level safety state machine and independent recovery boundary above those mechanisms.

For the current provider API, see `src/agent_containment/enforcer.py`.

## Stateful policy enforcement

Policies can reason about action sequences rather than only individual actions.

```python
from agent_containment.policy import PolicyEngine, SequenceRule

policy = PolicyEngine(sequence_rules=[
    SequenceRule(
        "prevent-download-upload-delete",
        ("download_file", "upload_file", "delete_file"),
    )
])
```

The controller can therefore allow:

```text
download_file → ALLOW
upload_file   → ALLOW
```

while halting the third action when the complete sequence is observed:

```text
delete_file → HALT
```

The policy history is maintained by the controller rather than being supplied by the agent.

## Standalone control plane

The repository includes a Unix-domain control transport and client for separating the agent from the controller process.

```text
Agent
  |
  | Unix domain socket
  v
agentcontainmentd
  |
  +-- peer credential authorization
  +-- action policy
  +-- stateful policy history
  +-- containment authority
  +-- audit/evidence
  |
  v
OS enforcement boundary
  |
  +-- cgroup v2
  +-- eBPF cgroup egress enforcement
```

The daemon exposes a deliberately narrow control protocol for registration, authorization, status, containment, reports, and snapshots.

## OS-level containment

On Linux, production deployments can place an agent and its descendants in a dedicated cgroup v2. Containment can then:

- invalidate application and egress leases;
- revoke application capabilities;
- activate the eBPF egress blocker;
- terminate the contained cgroup;
- preserve controller-owned evidence and telemetry paths.

The strongest guarantees depend on deployment privileges, cgroup configuration, kernel support, and correct isolation. AgentContainment does **not** claim that completed external side effects can be reversed.

See `docs/OS_LEVEL_CONTAINMENT.md` and `docs/EGRESS_CONTAINMENT.md` for the security model and limitations.

## Audit evidence

The controller can maintain a JSONL hash chain linking each event to the previous event. Verification detects edits, deletion, and reordering of the recorded chain.

This is **tamper-evident**, not immutable storage: an attacker with authority to rewrite both the audit file and its trusted reference can rewrite the evidence. External anchoring is a future hardening layer.

## Agent hierarchy

`AgentTree` models parent/child agents and propagates containment through currently registered descendants. Child capabilities are attenuated to the intersection requested by the child and held by the parent.

This provides a foundation for multi-agent containment without assuming that every child has the same authority as its parent.

## Status

**Early research/prototype.** The project is currently focused on deterministic authorization, stateful action policy, runtime fencing, provider-neutral enforcement verification, containment, child-agent propagation, OS-level Linux enforcement, incident evidence, and optional Cilium network enforcement. Cilium/Tetragon remain optional integrations rather than core dependencies.

The project should not yet be treated as a production security boundary without validating the host deployment, privilege model, identity binding, policy coverage, and kernel enforcement configuration.

## Repository layout

- `src/agent_containment/` — core library and controller components
- `ebpf/` — Linux eBPF enforcement program and controller
- `policies/` — example policy
- `demo/` — controlled rogue-agent demonstration
- `tests/` — security and behavior tests
- `tests/integration/` — opt-in privileged Linux integration tests
- `docs/` — architecture, threat model, and containment notes
- `scripts/` — build and development helpers

## Safety

The demo uses a simulated environment. It does not execute destructive actions against real infrastructure.

Privileged integration tests are opt-in and intended for isolated Linux environments.

## License

Apache-2.0
