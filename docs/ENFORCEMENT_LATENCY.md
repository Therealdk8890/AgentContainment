# Enforcement Latency Proof

Containment correctness is not only about whether the controller survived. The system must distinguish the decision/request from the point at which an external provider was applied and independently verified.

The current report records monotonic checkpoints for:

1. containment_requested_at — controller begins the containment transaction;
2. provider_applied_at — an external provider reports successful application;
3. independently_verified_at — the provider verification path reports the boundary established.

`enforcement_latency_seconds` measures request → independent verification.

These timestamps are diagnostic timing evidence, not wall-clock provenance. Controller-owned governance events remain the source for externally correlated timestamps and audit records.

## Provider semantics

Different providers have different enforcement characteristics:

- cgroup v2 process containment is a kernel-local boundary;
- cgroup egress/eBPF enforcement is also established at a kernel boundary;
- distributed network policy systems can have control-plane propagation delay.

A provider must not be described as effective merely because authorization returned HALT. Certification requires the provider-specific `verify_contained()` observation.

## Next proof requirement

Real-host tests should additionally measure the interval against a protected action attempt and record whether the action completed during that interval.

```text
decision
  ↓
containment request
  ↓
provider boundary applied
  ↓
independent observation
  ↓
effective enforcement
```

The repository must keep these concepts separate rather than collapsing them into a single contained boolean.
