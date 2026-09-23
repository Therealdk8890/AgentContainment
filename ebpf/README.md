# eBPF containment proof of concept

This directory contains the Linux kernel-side egress blocker used by the privileged integration test.

The program is intentionally simple: it is attached to a dedicated cgroup only when containment is triggered, and returns `0` for every egress packet from that cgroup. Before attachment, the cgroup has no AgentContainment egress filter.

## Requirements

- Linux with cgroup v2
- clang with BPF target support
- libbpf development headers/library
- root or equivalent BPF/cgroup privileges

The normal unit-test suite does not require these privileges.

## Build

Run `scripts/build_ebpf.sh` on a Linux host. It produces:

- `build/agent_containment_egress.bpf.o`
- `build/agent_containment_ebpf_ctl`

The controller attaches the program to a supplied cgroup and pins the link under a controller-owned directory. Removing the pin detaches the program.

## Security boundary

The eBPF object is not loaded by the agent. A trusted containment controller, running with the required host privileges, performs the attachment. The agent therefore cannot grant itself the ability to disable the blocker.