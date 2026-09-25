# Egress Containment

AgentContainment treats network egress as a separate enforcement boundary.

## Security invariant

The portable framework guarantees that once the runtime is CONTAINED, all
outstanding egress leases are invalid and registered in-flight connections are
requested for teardown.

A hardened deployment can strengthen this to: once containment is established,
no process in the contained runtime can transmit externally observable network
traffic. That stronger guarantee requires OS-level enforcement; a Python
library cannot prevent an arbitrary subprocess or raw socket from bypassing
application code.

## Enforcement layers

1. Epoch fencing with EgressLease(agent_id, epoch).
2. Dual-check authorization before and immediately before the network side effect.
3. Connection registry with hard teardown callbacks.
4. Process isolation using process groups, cgroups, containers, or PID namespaces.
5. Linux kernel egress enforcement using cgroup/eBPF or equivalent controls.
6. Out-of-band forensics over local IPC such as a Unix domain socket. The
   controller owns external telemetry egress.

## Linux eBPF proof

The privileged integration test exercises the actual cgroup/eBPF boundary rather
than only the Python egress gate:

1. A raw Python socket connects to a local TCP listener before containment.
2. The workload is placed in a dedicated cgroup.
3. The controller attaches the eBPF cgroup_skb/egress program to that cgroup.
4. The program returns 0 at the kernel egress hook, which means DROP for a
   cgroup skb program.
5. The same uncooperative workload attempts a second raw socket connection
   after containment without consulting AgentContainment or its leases.
6. The connection attempt fails and the listener receives no post-containment
   connection.

The test therefore distinguishes application-level lease invalidation from a
host-enforced network decision. A successful run is evidence that the kernel
hook blocked new egress from the protected cgroup on the tested Linux host and
kernel; it is not a universal claim across kernels, network namespaces, or
external enforcement layers.

## Abortive socket close

hard_close_socket() configures SO_LINGER with a zero timeout where supported,
then closes the socket. This requests an abortive TCP close instead of the
normal graceful close behavior.

This is a transport primitive, not a universal guarantee. Packets already
transmitted, remote buffering, UDP semantics, proxies, and retries can affect
what has already become externally observable.

## Threat model boundary

AgentContainment does not claim to reverse completed side effects. Its goal is
to stop further authority and further network activity as close to the
containment boundary as the deployment's enforcement layer permits.
