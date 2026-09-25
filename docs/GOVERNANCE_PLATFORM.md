# Governance platform contract

AgentContainment is the **control and enforcement** layer in a broader AI-agent
governance stack. It does not need to own provenance storage or claim
verification to make those systems useful.

## Governance loop

```text
Observe → Prove → Authorize → Enforce → Contain → Recover → Regression
   ↑                                                        │
   └──────────────────── release gate ◄─────────────────────┘
```

The separation of responsibilities is deliberate:

| Layer | Primary question | Responsibility |
| --- | --- | --- |
| DProvenanceKit | What happened? | Trace, evidence, cryptographic provenance, regression evidence |
| AgentContainment | What was allowed? | Authorization, containment authority, recovery authority, enforcement verification |
| ClaimProofKit | Is the claim supported? | Claim/evidence relationships and support verification |
| Hosted control plane | How is it operated? | Inventory, policy management, incidents, RBAC, retention, dashboards, CI/CD integration |

These are integration boundaries, not runtime dependencies.

## Stable event contract

The `GovernanceEvent` envelope is the controller-owned contract intended for
downstream provenance ingestion.

Core identifiers are:

- `event_id`
- `event_type`
- `timestamp`
- `agent_id`
- `trace_id`
- `run_id`
- `action_id`
- `policy_decision_id`
- `incident_id`
- `containment_epoch`

Optional `attributes` carry provider-specific details without changing the
top-level contract.

AgentContainment emits lifecycle events including authorization decisions,
containment requests, capability revocation, enforcement, certification or
verification failure, recovery requests/authorization/completion, and proof
degradation.

### Authority boundary

The event sink is **downstream**. Failure to deliver a governance event must
not prevent containment, recovery fencing, or other controller decisions.
Consumers must therefore treat events as an integration stream rather than the
security boundary itself.

A provenance system may persist and cryptographically bind these events, but
it must not become the authority that decides whether a runtime is allowed to
recover.

## Incident → regression

A contained incident can be exported as a `RegressionFixture`.

The fixture intentionally contains identifiers and expected behavior rather
than copying evidence documents:

```text
incident
  ├─ agent identity / version
  ├─ task context
  ├─ action sequence
  ├─ policy decision
  ├─ evidence references
  ├─ containment result
  └─ expected future behavior
          │
          ▼
   deterministic regression case
          │
          ▼
       release gate
```

This allows DProvenanceKit and ClaimProofKit to attach richer evidence without
forcing AgentContainment to understand their internal representations.

A useful future regression gate is:

1. reproduce the trigger;
2. observe the same action sequence;
3. obtain the expected authorization decision;
4. require the expected containment response;
5. verify that no bypass occurred;
6. optionally verify that resulting claims are supported by the attached
   evidence.

## Integration contract

A downstream governance platform should be able to answer:

1. What did the agent attempt?
2. What policy decision was made?
3. What evidence is associated with the action?
4. Why was containment requested?
5. Was enforcement independently verified?
6. Who or what authorized recovery?
7. Did the incident become a repeatable regression case?
8. If the agent made a factual claim, is that claim supported by evidence?

AgentContainment owns questions 2, 4, 5, and the recovery boundary. Provenance
and claim-verification systems own the evidence needed to answer the others.

## Productization path

### Phase 1 — Open primitives

- stabilize controller lifecycle events;
- define the shared event envelope;
- export incidents as regression fixtures;
- keep provider integrations optional;
- document security boundaries and failure modes.

### Phase 2 — Local governance bundle

Provide a reference integration that connects:

```text
Agent
  │
  ▼
AgentContainment ─────► GovernanceEvent
  │                         │
  │                         ▼
  │                    DProvenanceKit
  │                         │
  │                         ▼
  └──────── incident ─► ClaimProofKit
                            │
                            ▼
                     regression fixture
```

### Phase 3 — Hosted control plane

The hosted layer can add organization-level concerns without moving the
containment authority into a dashboard:

- agent inventory;
- policy management;
- incident timelines;
- provenance/evidence exploration;
- containment status;
- regression history;
- CI/CD gates;
- RBAC;
- retention and audit export;
- deployment/provider configuration.

### Phase 4 — Vertical applications

A vertical product such as CaseClarity can consume the same governance
primitives for delegated legal research and document workflows while keeping
the generic control/provenance/claim layers reusable.

## Security boundaries and non-goals

- A provenance record does not prove an action was safe.
- A Kubernetes policy object does not by itself prove that the datapath
  enforced it.
- A claim verifier does not contain an agent.
- Containment cannot undo external side effects that already occurred.
- A dashboard is not a security boundary.
- The governance stack does not eliminate deployment-specific host, kernel,
  identity, credential, and network controls.

The central design rule remains:

> **Proof can explain what happened. Verification can establish what is
> supported. Control must independently retain authority to stop and recover
> the runtime.**
