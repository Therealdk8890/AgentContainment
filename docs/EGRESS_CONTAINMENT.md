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
