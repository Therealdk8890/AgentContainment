# Changelog

## 0.1.3 — 2026-10-31

### Added

- Reject recovery authorizations issued by a controller instance that has been discarded by a process restart; callers must obtain fresh recovery authorization from the restarted controller.
- Extend restart-boundary regression coverage for stale recovery capabilities before and after external enforcement reconciliation.

### Fixed

- Reconcile a crash after external enforcement release but before the incident record is committed, preserving fail-closed recovery behavior.
- Make the delegated-cgroup child-process integration test resolve the package source reliably after dropping privileges, and clean up its staged import tree.

## 0.1.2 — 2026-10-11

Security fix for forged execution leases.

- Bind each `ExecutionLease` to runtime-issued provenance in addition to agent identity and epoch.
- Reject caller-constructed leases that merely match the active agent and epoch before executing a side effect.
- Add a regression test asserting a forged lease is denied and the executor is never called.
- Preserve the existing trust boundary: the Python controller/runtime must remain outside the agent's process and privilege boundary; the private proof object is not isolation against hostile code running inside the controller process.

## 0.1.0 — 2026-09-25

Initial public release of AgentContainment.

### Included

- Controller-owned action authorization and stateful policy enforcement.
- Durable admission/epoch fencing and capability revocation during containment.
- Unix-domain controller transport with peer-credential authorization.
- Linux cgroup v2 process containment.
- Linux eBPF cgroup egress enforcement.
- Independent enforcement verification rather than treating an accepted command as proof of containment.
- Child-agent containment propagation with attenuated capabilities.
- Tamper-evident controller-owned audit evidence.
- Warden read-only observation boundary.
- Incident-derived regression fixtures and release-gate replay tests.
- Provider-neutral enforcement interfaces with optional Cilium/Tetragon integration targets.

### Scope

AgentContainment 0.1.0 is an early research/prototype release. It is not a claim of production security or universal kernel-level isolation. Production deployments must validate host privileges, cgroup configuration, workload identity binding, policy coverage, kernel support, enforcement configuration, and recovery procedures on the target environment.
