# Provenance Bridge

## Purpose

AgentContainment emits controller-owned `GovernanceEvent` records. The provenance bridge converts those events into immutable `ProvenanceRecord` snapshots that can be consumed by DProvenanceKit or another evidence system.

The core package intentionally does **not** depend on DProvenanceKit. Integration is by the existing event-sink boundary.

```text
ContainmentService
      |
      | GovernanceEvent
      v
ProvenanceEmitter
      |
      v
ProvenanceSink
      |
      +--> DProvenanceKit adapter
      +--> local evidence store
      +--> test collector
```

## Security boundary

The direction is one-way:

- AgentContainment owns authorization, containment, enforcement verification, and recovery.
- Provenance consumers receive snapshots of controller-owned events.
- Provenance consumers cannot authorize an action, release containment, or mutate controller state through this interface.
- A provenance sink failure is evidence degradation only. It must never block or weaken containment.

`ContainmentService` already treats governance event sink failures as downstream failures. `ProvenanceEmitter` follows the same rule and returns `False` when its sink cannot accept an event.

## Stable record

`ProvenanceRecord` preserves:

- event identity and type;
- controller timestamp;
- agent, trace, run, and action identity;
- policy decision and incident identity;
- containment epoch;
- reason and attributes.

Attributes are serialized into a canonical JSON representation at the boundary so downstream consumers cannot mutate the source event through a shared mutable mapping.

## DProvenanceKit integration

A DProvenanceKit adapter can implement `ProvenanceSink.append(record)` and translate the stable record into the provenance library's native evidence model. That adapter belongs outside AgentContainment's core dependency set.

The intended relationship is:

```text
DProvenanceKit: PROVE
        ^
        | immutable event snapshots
        |
AgentContainment: CONTROL
        |
        +--> external enforcement
```

Provenance is evidence about the control lifecycle; it is not the control lifecycle's authority.
