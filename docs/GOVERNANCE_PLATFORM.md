# Governance Platform Architecture

## Purpose

AgentContainment is the control and enforcement primitive in a larger AI-agent governance system. The platform combines three capabilities:

1. **Provenance** — prove what the agent did and what evidence supported it.
2. **Control** — determine what the agent is allowed to do and independently contain violations.
3. **Regression** — turn observed failures and containment incidents into repeatable release gates.

The platform should preserve a hard security boundary: provenance and containment may be integrated, but an agent must never be able to authorize its own recovery or rewrite controller-owned incident evidence.

## Closed governance loop

`Observe → Prove → Authorize → Enforce → Contain → Recover → Regression`

### Normal execution

```text
Agent
  |
  v
Action request
  |
  +----> Provenance event
  |
  v
Authorization policy
  |
  +---- ALLOW ----> tool/runtime
  |
  +---- DENY/HALT ----> incident
```

### Incident execution

```text
Policy violation / anomaly
        |
        v
    DETECT
        |
        v
     PROVE
        |
        v
      HALT
        |
        v
    CONTAIN
        |
        +---- revoke capabilities
        +---- fence runtime
        +---- block network
        +---- preserve evidence
        |
        v
      MAP
        |
        v
   RECOVERY AUTHORITY
        |
        v
   Regression case
```

## Integration contract

The integration between DProvenanceKit and AgentContainment should be event-oriented rather than tightly coupled.

A governance event should have stable identifiers such as:

- `trace_id`
- `agent_id`
- `run_id`
- `action_id`
- `policy_decision_id`
- `incident_id`
- `containment_epoch`
- `timestamp`
- `event_type`

AgentContainment should emit lifecycle events for:

- authorization decision
- containment requested
- containment enforced
- enforcement verification
- containment certified
- capability revocation
- recovery requested
- recovery authorized
- recovery completed
- recovery denied
- provider degradation

DProvenanceKit can bind those events into the provenance/evidence trail without becoming the authority that performs containment.

## Incident-to-regression pipeline

A contained incident should be exportable as a deterministic regression fixture.

Minimum fixture fields:

```text
incident_id
agent identity
agent/version
task/context
action sequence
policy decision
evidence references
containment result
expected future behavior
```

The resulting regression gate should be able to assert:

```text
same trigger
    →
same policy decision
    →
same containment requirement
    →
no previously observed bypass
```

This is the mechanism that turns production safety failures into continuously enforced engineering knowledge.

## Platform boundaries

### AgentContainment owns

- authorization and policy state
- containment authority
- durable admission fencing
- recovery authority
- external enforcement verification
- containment lifecycle

### Provenance layer owns

- trace/evidence representation
- cryptographic provenance
- evidence relationships
- regression evidence
- export/verification of provenance records

### Hosted control plane eventually owns

- organization and agent inventory
- policy management
- incident dashboard
- provenance explorer
- deployment/provider configuration
- RBAC
- retention and evidence storage
- CI/CD gates
- audit exports

The hosted layer must not move the containment authority inside the agent process merely for convenience.

## Productization sequence

### Phase 1 — Open primitives

- stabilize AgentContainment provider contracts
- stabilize provenance event schema
- define the cross-project governance event envelope
- add incident export → regression fixture
- document the security boundary

### Phase 2 — Local governance bundle

Provide a reference integration that runs entirely locally:

```text
Agent
  |
  +--> DProvenanceKit
  |
  +--> AgentContainment
          |
          +--> cgroup/eBPF
          +--> Cilium
          +--> Tetragon
```

No hosted service should be required for the core safety loop.

### Phase 3 — Hosted control plane

Add:

- agent inventory
- policy editor
- incident timeline
- provenance/evidence viewer
- containment status
- regression history
- CI integration
- organization-level RBAC
- managed evidence retention

### Phase 4 — Vertical application

CaseClarity can consume the same governance primitives for delegated legal research and document workflows.

The vertical product should expose business outcomes rather than infrastructure primitives while retaining the same underlying evidence and containment model.

## Non-goals

The platform should not claim:

- that provenance proves an agent was harmless;
- that a Kubernetes policy object alone proves datapath enforcement;
- that containment reverses completed external side effects;
- that a hosted dashboard is itself a security boundary;
- that an AI governance platform eliminates the need for deployment-specific security controls.

## Success criteria

The architecture is working when an operator can answer, for any governed run:

1. **What did the agent attempt?**
2. **What was it authorized to do?**
3. **What evidence supports that record?**
4. **What enforcement actually occurred?**
5. **Why was containment triggered?**
6. **Was containment independently verified?**
7. **Who/what authorized recovery?**
8. **Was the incident converted into a future regression gate?**

That is the core product loop: **prove, control, and continuously validate autonomous AI behavior.**
