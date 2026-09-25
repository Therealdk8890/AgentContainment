# Controller Isolation & Authority Boundary

## Purpose

Milestone 8A makes the controller's trust boundary explicit.

The controller is not safe merely because it is a separate Python object or
daemon. A compromised agent must not be able to terminate, impersonate,
modify, starve, or otherwise interfere with the process that owns
authorization and containment authority.

The target property is:

> **The agent cannot interfere with the controller's execution, IPC, resources,
> credentials, namespace, or lifecycle before the controller can enforce
> containment.**

## Required topology

```text
                    HOST / CONTROL PLANE

        +---------------------------------------+
        | AgentContainment controller           |
        | dedicated service UID                 |
        | dedicated controller cgroup           |
        | controller-owned Unix socket           |
        |                                       |
        | AUTHORIZE → CONTAIN → RECOVER         |
        +-------------------+-------------------+
                            |
                     kernel control plane
                            |
        +-------------------v-------------------+
        | Agent workload                        |
        | separate UID / cgroup / namespaces    |
        |                                     |
        | untrusted agent + descendants         |
        +---------------------------------------+
```

### Current UID model

The daemon currently **inherits the UID of the process that launches it**. AgentContainment does not yet force a dedicated service UID in Python itself.

That distinction matters:

- in a production deployment, the service manager should run `agentcontainmentd` as a dedicated controller UID/GID;
- the agent workload should run as a different, less-privileged identity;
- the controller's privileged UID should never be inferred from an agent-provided request;
- development deployments that run both under the same UID do **not** establish the intended Unix permission boundary and must not be treated as isolation evidence.

The daemon's privileged transport commands now fail closed when no UID allowlist is configured: the only implicit privileged identity is the daemon's own effective UID.

The controller must be outside the agent's trust boundary. The agent-facing
IPC path, if one is required, must expose only the minimum operations needed
by the workload and must authenticate the peer independently of application
claims.

## What this milestone proves

The real-host integration test exercises the boundary rather than relying on
a diagram:

- an unprivileged agent cannot signal the controller;
- the agent cannot ptrace or open the controller's protected process state;
- the agent cannot connect to a controller socket protected for the control
  identity;
- controller and agent occupy distinct cgroups;
- controller-owned privileged commands fail closed when no explicit
  privileged-UID policy is supplied.

These tests are evidence for the configured Linux deployment, not a universal
claim about every container, namespace, or service-manager configuration.

## Fail-closed rule

The daemon must never interpret an omitted privileged-UID policy as
"every local peer is privileged."

The safe default is:

- privileged commands are available only to the daemon's own effective UID;
- additional authorized peers must be explicitly configured;
- agent authorization, where required, uses an explicitly configured
  non-privileged peer identity plus the existing workload-bound identity token.

## Deployment hardening

For production, the controller should additionally be managed by a host
service manager or equivalent trusted supervisor with:

- a dedicated service UID/GID;
- a dedicated controller cgroup;
- no shared writable filesystem with the agent;
- a controller-owned IPC endpoint with restrictive ownership/mode;
- no ptrace relationship from the agent;
- independent CPU/memory/resource controls;
- restart policy independent of the agent;
- minimal capabilities required to perform containment;
- namespace and filesystem restrictions appropriate to the host deployment.

The exact capability and namespace profile must be derived from the enforcement
providers actually enabled. Over-restricting the controller can make
containment fail; under-restricting it can collapse the trust boundary.

## Important architectural consequence

Static kernel constraints should establish the agent's **initial safety
floor** before the agent starts.

The controller should then primarily perform state transitions that make the
workload **more restricted**, terminate it, or authorize narrowly scoped
operations through already constrained mechanisms.

This means controller failure should not silently convert into unrestricted
agent capability.

## Bootstrap boundary

Runtime isolation is insufficient if an attacker can prevent the controller from
starting or replace what the trusted supervisor starts.

A production deployment therefore needs a bootstrap chain such as:

```text
trusted host / image
      ↓
service-manager policy
      ↓
controller binary + configuration
      ↓
controller process
      ↓
agent admission
```

The agent must not have write access to:

- the controller executable or Python environment;
- the controller configuration and service definition;
- the controller socket directory;
- the controller's service UID/GID;
- the service-manager control interface.

Startup should establish the agent's kernel safety floor before the agent is
admitted. If the controller fails to start, the safe outcome is **no agent
admission**, not an unrestricted workload.

## Enforcement latency

Controller survivability and enforcement latency are separate security
properties.

For every enforcement provider, measure:

```text
AUTHORIZE/HALT decision
        ↓
containment request
        ↓
provider boundary applied
        ↓
independent observation
        ↓
effective enforcement
```

The measured interval must be provider-specific. cgroup-based process
termination and freezing can be kernel-synchronous at the relevant boundary;
network policy systems that require control-plane propagation can introduce a
window.

The real-host proof must therefore record or bound:

- decision timestamp;
- containment request timestamp;
- provider application timestamp where available;
- independent enforcement-observation timestamp;
- whether the agent completed the protected action during the interval.

Do not describe a policy as "enforced" merely because AUTHORIZE returned HALT.

## Security questions

Before calling the controller boundary production-grade, answer these with
host-level tests or deployment-specific evidence:

1. Can the agent kill or signal the controller?
2. Can the agent ptrace the controller?
3. Can the agent modify controller binaries, state, or IPC endpoints?
4. Can the agent impersonate an authorized control peer?
5. Can the agent exhaust controller CPU or memory?
6. Can the agent enter or modify the controller's cgroup?
7. Can controller restart/recovery be raced by the agent?
8. What safety guarantees remain if AUTHORIZE crashes?
9. Can the agent obtain a capability that allows it to authorize its own
   recovery?

The acceptance criterion is not "the daemon runs separately."

It is:

> **A compromised agent cannot make the controller unable to enforce its
> controller-owned authorization and containment decisions before those
> decisions take effect.**
