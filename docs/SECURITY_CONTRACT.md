# AgentContainment Security Contract

Status: v0.1 research/prototype contract

AgentContainment is designed around one security boundary: the AI agent is untrusted, while the controller and host enforcement mechanisms are trusted security components.

## Security invariants

A conforming deployment MUST establish evidence for these invariants:

1. **Controller survivability** — an untrusted agent cannot terminate, ptrace, or otherwise directly compromise the controller through the tested host interfaces.
2. **Delegated containment boundary** — an untrusted agent cannot migrate a process into the controller-owned containment subtree from outside that delegated boundary.
3. **Forced termination** — the controller can terminate a contained workload without cooperation from the workload.
4. **Epoch freshness** — authority from an expired execution epoch cannot be reused to authorize a later execution.
5. **Host-enforced egress** — network restrictions are enforced by infrastructure outside the agent's cooperation.
6. **Recovery after partial failure** — controller recovery restores a known containment state after supported partial failures.
7. **Proof-state integrity** — missing, stale, degraded, or tampered evidence is distinguishable from a verified containment state.

## Adversarial validation

The privileged CI suite is the authoritative integration path for host-boundary claims. It runs only on maintainer-controlled pushes and exercises Linux cgroup/eBPF behavior on the CI host.

Current evidence includes:

- controller isolation attack paths
- systemd `Delegate=yes` cgroup delegation
- non-root subtree management
- cross-boundary cgroup migration denial
- workload termination through `cgroup.kill`
- eBPF containment build and privileged integration

A green CI run is evidence that the tested invariant held on that host and kernel configuration. It is not a universal proof for every Linux distribution, kernel, runtime, or deployment configuration.

## Proof-driven product direction

The product should integrate with existing workload sandboxes rather than require replacing them. The containment layer is intended to provide an independent control boundary and inspectable evidence around an untrusted agent workload.

The target operator experience is:

`policy -> admit -> contain -> detect -> fence -> halt -> verify -> recover -> receipt`

The receipt should identify the execution identity/epoch, policy state, enforcement mechanisms exercised, observed adversarial events, containment result, recovery state, and proof status.

## Threat-model discipline

Security claims MUST distinguish:

- implemented and tested controls
- implemented controls without adversarial integration evidence
- planned controls
- assumptions about the host/runtime
- claims that depend on external sandbox implementations

No feature should be described as a security guarantee merely because the agent is configured not to perform the behavior. Controls relevant to the boundary must be enforced outside the agent trust domain.

## Next proof milestones

- stale-epoch authority rejection — **implemented and adversarially tested**
  - old execution leases are rejected after containment and recovery epoch transitions
- host-enforced egress denial — **implemented and adversarially tested**
  - privileged CI observes a raw socket succeed before containment and fail after the controller attaches the cgroup/eBPF egress blocker
  - the listener receives no post-containment connection, separating kernel enforcement from application cooperation
- partial-failure recovery
- proof receipt integrity/tamper detection
- reproducible hostile-agent demonstration covering the complete lifecycle

This document is a security contract and test roadmap, not a claim of formal verification.
