# Adversarial Testing

The adversarial harness is a controlled simulation. It models hostile agent behavior without touching real infrastructure.

## Invariants

The prototype must preserve these invariants:

1. Every tool action crosses the gateway.
2. A halted runtime cannot execute another action.
3. A policy violation causes an immediate halt.
4. Explicit containment revokes every capability.
5. The agent cannot authorize itself after containment.
6. Tests must fail if an action bypasses the enforcement point.

## What this does not prove

Passing these tests does **not** prove OS, container, cloud, network, IAM, or process-level containment. Those require real adapters and integration tests.

## Next attack classes

- child-agent spawning and propagation of containment
- credential revocation races
- network egress after containment
- stale authorization tokens
- gateway restart/failover
- concurrent actions during a halt
- tampered incident evidence
- recovery of reversible side effects
