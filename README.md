# AgentContainment

**Runtime containment and enforcement for autonomous AI agents.**

AgentContainment is a framework-agnostic control plane designed to intercept agent actions, enforce policy, halt compromised runs, revoke authority, contain blast radius, and preserve verifiable incident evidence.

## Core model

`Detect → Prove → Halt → Contain → Map → Recover`

The containment plane is designed to sit **outside the agent's trust boundary**. An agent must not control its own kill switch, containment policy, credentials, or incident evidence.

## Why AgentContainment

Traditional agent guardrails often operate inside the application or framework executing the agent. AgentContainment is designed around a different security boundary:

> **The agent requests an action. The controller decides whether it is allowed. The enforcement layer can then stop the runtime and its network egress independently of the agent.**

This separation is intended to remain useful when an agent is compromised, misbehaving, or attempting to bypass its normal tool wrapper.

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

**Early research/prototype.** The project is currently focused on deterministic enforcement, stateful action policy, runtime fencing, containment, child-agent propagation, OS-level Linux enforcement, and incident evidence.

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
