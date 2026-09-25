# Incident evidence chain

Milestone 10 adds a tamper-evident, hash-linked incident evidence chain.

## Purpose

The chain binds the controller lifecycle into one verifiable sequence:

`action → policy decision → detection → containment request → enforcement result → Warden observation → containment verification → recovery authorization`

The current primitive is provider-neutral. It can consume controller events, enforcement results, and Warden observations without granting the evidence layer any control authority.

## Integrity model

Each node contains:
- sequence number;
- controller event identity;
- event type and timestamp;
- agent and incident identity;
- containment epoch;
- canonical payload snapshot;
- SHA-256 hash of the previous node;
- SHA-256 hash of the current node.

Verification recomputes every node and every link from the genesis hash.

This detects:
- payload mutation;
- event deletion;
- event insertion;
- event reordering;
- broken hash links;
- non-contiguous sequence numbers.

## Authority boundary

The chain is **proof material, not control state**.

A valid chain cannot authorize an action, establish containment by itself, release an agent, or grant recovery. AgentContainment's controller-owned incident registry, runtime fence, and enforcement layer remain authoritative.

Likewise, a chain entry saying `containment_enforced` records the controller's emitted fact. Independent enforcement and Warden observation must be included before downstream systems describe an incident as externally verified.

## DProvenanceKit relationship

The chain is designed to feed the existing optional DProvenanceKit adapter. DPK can retain, query, and cryptographically bind the resulting evidence, while AgentContainment remains the authority that controls the runtime.

`IncidentEvidenceChain.digest()` provides a deterministic chain-level commitment that can be attached to a downstream provenance record.