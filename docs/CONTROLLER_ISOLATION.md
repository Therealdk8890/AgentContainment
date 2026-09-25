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
        |                                       |
        | untrusted agent + descendants         |
        +---------------------------------------+
```

### Current UID model

The systemd deployment now **does force a dedicated controller service identity**:

- `systemd/agentcontainment.service` runs as `User=agentcontainment` and `Group=agentcontainment`;
- the example agent workload runs as the separate `agent` identity;
- the controller and agent therefore do not share the same Unix service identity in the documented systemd deployment;
- the daemon itself still does not hard-code a UID in Python. That is intentional: identity is a deployment boundary owned by the trusted service manager rather than an application-level assumption.

The dedicated `agentcontainment` system user/group must exist before the unit is started. The unit does not create accounts automatically.

For example, a host administrator can provision the identity with:

```bash
sudo groupadd --system agentcontainment
sudo useradd --system --gid agentcontainment --no-create-home   --shell /usr/sbin/nologin agentcontainment
```

Then install/enable the unit through the normal systemd workflow.

Development deployments that run the daemon and agent under the same UID do **not** establish the intended Unix permission boundary and must not be treated as isolation evidence.

The daemon's privileged transport commands fail closed when no UID allowlist is configured: the only implicit privileged identity is the daemon's own effective UID.

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

The repository also contains regression tests that verify the systemd unit
continues to specify a dedicated controller identity and the expected service
hardening directives.

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

The included systemd unit already establishes the dedicated UID/GID,
controller-owned runtime directory, restrictive umask, filesystem protections,
kernel protection settings, and `NoNewPrivileges=yes`. It deliberately leaves
`ProtectControlGroups=no` because the controller may need to manage the
cgroup hierarchy used for containment.

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
admitted. The included example systemd workload makes this explicit: it has a
`Requires=agentcontainment.service` dependency, starts only after the
controller, and runs an `ExecStartPre` check for the controller-owned Unix
socket. If the controller fails to start or the socket is absent at admission,
the workload is not started. `PartOf=agentcontainment.service` also propagates
controller lifecycle changes to the example workload.

This is a bootstrap/readiness floor, not proof that the controller's full
enforcement policy is healthy. The socket check establishes that the controller
has reached its transport-start phase; deployment-specific readiness checks
should be added if a workload requires stronger controller health semantics.

If the controller fails to start, the safe outcome is **no agent admission**,
not an unrestricted workload.

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
\nThe controller's cgroup authority is also delegated explicitly by systemd. The service unit uses `Delegate=yes` and starts the daemon with `--cgroup-root auto`. The daemon derives its cgroup v2 path from `/proc/self/cgroup` and creates an `agents/` subtree beneath its own delegated service cgroup. This avoids requiring the controller to be root while avoiding a hard-coded `/sys/fs/cgroup` directory that an unprivileged service would not own.

The controller unit no longer creates or moves itself into a sibling cgroup. Its systemd service cgroup is the control-plane boundary; workload cgroups are children of that delegated boundary. Linux cgroup v2 delegation permits a non-root delegatee to create and manage a subtree while preventing it from moving processes across the delegation boundary. citeturn0search1turn0search0

