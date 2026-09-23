# Child-Agent Containment

Autonomous systems increasingly create sub-agents. A containment boundary that only stops the original agent is incomplete: descendants can otherwise continue operating with inherited authority.

## Model

AgentContainment maintains an execution tree:

```text
parent-agent
├── child-agent
│   └── grandchild-agent
└── child-agent-2
```

Each node has its own runtime and capability set. The tree itself is the authority that knows the parent/child relationship.

## Propagation invariant

When an agent is contained:

1. The target runtime enters `CONTAINED`.
2. Its capabilities are revoked.
3. Every registered descendant is contained recursively.
4. Descendant capabilities are revoked.
5. A contained parent cannot spawn a new child.
6. A contained descendant cannot pass the gateway and execute another action.

## Capability inheritance

A child starts with the intersection of:

- the parent's currently available capabilities
- the capabilities explicitly requested for the child

This makes child creation a narrowing operation rather than an authority expansion.

## Security boundary

The agent does not control the tree. It cannot declare itself contained, release another agent, or bypass propagation.

The current implementation is an in-process reference model. Production adapters still need to connect containment to actual process termination, container orchestration, IAM/session revocation, network controls, and provider-specific agent runtimes.

## Test coverage

The adversarial tests cover:

- parent → child capability inheritance
- capability narrowing
- parent → child → grandchild propagation
- blocked child creation after parent containment
- descendant capability revocation
- unknown-agent rejection
