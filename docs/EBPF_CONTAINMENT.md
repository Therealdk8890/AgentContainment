# Linux eBPF Egress Containment

This proof of concept moves the network kill switch below the Python runtime boundary.

## Enforcement model

1. The agent runs inside a dedicated cgroup v2.
2. Normal operation has no AgentContainment egress filter attached.
3. Containment first transitions the runtime to `CONTAINED` and revokes application capabilities.
4. A privileged controller attaches `agent_containment_egress` to the agent cgroup.
5. The eBPF program returns `0` for every egress packet, causing the cgroup egress hook to drop it.
6. The controller can then kill the cgroup with `cgroup.kill`.

The important property is that the agent does not own the BPF program, attachment, or pin directory.

## What this proves

The privileged integration test uses a child process inside the cgroup and a local TCP listener outside it. The child establishes a TCP connection before containment. After the blocker is attached, a new TCP connection and subsequent egress are expected to fail.

This demonstrates enforcement below the agent's Python/tool abstraction. It is not a claim that packets already accepted by a remote peer can be recalled.

## Limitations

- BPF and cgroup operations require host privileges and kernel support.
- The dedicated cgroup must be configured so the agent and its descendants cannot escape to another cgroup.
- The test is opt-in and skipped by ordinary CI.
- A packet already transmitted before the kernel hook is attached may reach its destination.
- Existing application-side connections may need separate termination; the egress filter blocks subsequent packets but does not magically undo remote side effects.
- Production deployments should use a hardened host/container policy and protect the BPF filesystem and controller credentials.