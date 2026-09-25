# DProvenanceKit adapter

AgentContainment owns authorization and enforcement. DProvenanceKit is an optional downstream provenance layer.

## Flow

    agent action
       |
       v
    AgentContainment controller
       |  GovernanceEvent
       v
    DProvenanceKitSink
       |  agent_containment.<event_type>
       v
    DProvenanceKitPython trace store

The adapter does **not** make DProvenanceKit a core dependency. Install DProvenanceKitPython separately when provenance recording is desired.

## Usage

```python
from agent_containment.control import ContainmentService
from agent_containment.dprovenancekit_adapter import DProvenanceKitSink

sink = DProvenanceKitSink(db_path=".dprovenance/containment.sqlite")

with sink.run(context_id="incident-123"):
    controller = ContainmentService(event_sink=sink)
    # Execute the normal controller-owned lifecycle here.
```

The adapter can also be composed through `ProvenanceEmitter`:

```python
emitter = sink.emitter()
emitter.emit(governance_event)
```

Sink failures are intentionally downstream failures. They must not change authorization, enforcement, containment, release, or recovery outcomes.

## Event contract

Every DPK event uses the stable namespace:

`agent_containment.<GovernanceEvent.event_type>`

The event attributes retain the immutable AgentContainment provenance record, including:

- `event_id`
- `timestamp`
- `agent_id`
- `trace_id`
- `run_id`
- `action_id`
- `policy_decision_id`
- `incident_id`
- `containment_epoch`
- `reason`
- controller-owned `attributes`

This preserves controller identity while allowing DProvenanceKit to query, diff, and retain the lifecycle as a local decision-path trace.

## Important limitation

A DPK record proves what AgentContainment emitted to the provenance layer. It does not independently establish that an enforcement action actually took effect. Enforcement evidence and Warden observation must be bound into the same incident evidence chain before making an enforcement-verification claim.