# Milestone 8 — Warden Observation Contract

## Objective

Milestone 8 adds the observability boundary above the proven containment path.

Warden is an **observation shell**, not another authorization or containment layer. It may observe and display the governance chain, but observation must be incapable of changing authorization or containment state.

## Security invariant

> **Warden observation must be incapable of changing authorization or containment state.**

The integration therefore uses a one-way, provider-neutral observation contract:

```text
Agent action
    ↓
Claim verification
    ↓
AgentContainment authorization
    ↓
External enforcement
    ↓
DProvenanceKit evidence
    ↓
Warden observation
```

Warden does not sit in the authorization path.

## Acceptance criterion

Given one agent action, an operator can reconstruct:

```text
action
  →
verification
  →
authorization
  →
enforcement
  →
evidence
```

from Warden without Warden having authority over any of those decisions.

## Initial implementation

WardenObservation is an immutable, provider-neutral representation of a controller-owned GovernanceEvent.

It:

- preserves stable governance identifiers;
- records the observed event type and containment epoch;
- carries trace/run/action/incident identifiers;
- serializes to deterministic JSON;
- declares its authority as observation-only;
- copies event attributes rather than retaining a mutable reference to the source mapping.

It deliberately does **not** expose methods to:

- authorize or deny an action;
- contain or release an agent;
- mutate a containment epoch;
- change enforcement state;
- approve recovery.

## Boundary tests

The initial tests verify that:

1. governance events can be converted into observations without losing correlation identifiers;
2. the observation advertises observation-only authority;
3. the observation does not mutate the controller-owned source event when its copied attributes are changed.

## Next integration stages

The remaining Milestone 8 work is intentionally incremental:

1. define the complete action/verification/authorization/enforcement/evidence event mapping;
2. add a provider-neutral Warden adapter on the observation side;
3. exercise the chain against the real Linux enforcement path proven in Milestone 7;
4. integrate provenance evidence without giving Warden authority;
5. add an end-to-end regression test proving the full chain is reconstructable;
6. document and test the invariant that Warden cannot mutate containment or authorization state.

No Warden integration should bypass the controller or become a second recovery authority.
