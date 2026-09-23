# Controller Plane

AgentContainment's controller plane is deliberately separate from the agent.

`ContainmentService` is the first transport-agnostic implementation of that boundary. It owns the registry of managed agents and invokes `ContainmentController` on behalf of the operator.

## Trust boundary

```text
agent process (untrusted)
        |
        | actions / telemetry
        v
+------------------------------+
| AgentContainment controller  |
| policy + containment authority|
+------------------------------+
        |
        +--> cgroup / eBPF
        +--> process termination
        +--> connection termination
        +--> incident evidence
```

The agent never receives the controller object. A production deployment should expose `ContainmentService` through a controller-owned local transport (for example a Unix-domain socket) or a mutually authenticated remote control plane.

## Security properties

- Registration rejects identity mismatches.
- Duplicate agent identities are rejected.
- Containment is controller initiated.
- Runtime fencing occurs before enforcement adapters.
- Enforcement failures leave the agent in `CONTAINED`.
- The transport layer is intentionally not part of the trusted agent SDK.

This is a control-plane primitive, not yet a production daemon. The next layer is a hardened Unix-domain-socket adapter with peer authentication and a small command protocol.
