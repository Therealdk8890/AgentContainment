# OS-Level Containment

AgentContainment now has explicit integration points for OS-level enforcement.

## Process containment

Production Linux deployments can place an agent and its descendants in a
dedicated cgroup v2. On containment, cgroup.kill terminates all processes in
that cgroup. This is stronger than killing one PID or relying only on a process
group.

The library accepts an existing cgroup path rather than creating or discovering
one automatically. Privileged host mutation therefore remains outside normal
library initialization.

## Kernel egress policy

KernelEgressEnforcer is an explicit boundary for a Linux cgroup/eBPF
implementation. The reference adapter writes a controller-owned deny state.
A production deployment should bind that state to a cgroup egress hook such as
BPF_CGROUP_INET_EGRESS so packets from the contained cgroup are dropped by the
kernel.

The reference adapter is NOT itself eBPF enforcement.

## Hardened topology

    controller
       |
       +---- evidence / telemetry egress
       |
       +---- containment state
       |
       v
    cgroup v2
       |
       +---- agent process
       +---- child processes
       |
       +---- eBPF cgroup egress policy
       |
       v
      NIC

Containment sequence:

1. Transition runtime to CONTAINED and increment the epoch.
2. Revoke application capabilities.
3. Flip kernel egress state to deny.
4. Kill the contained cgroup.
5. Preserve controller-owned evidence and telemetry paths.

This is defense in depth. Correct host privileges, cgroup configuration,
network policy, and container isolation are required for the strongest
guarantees.
