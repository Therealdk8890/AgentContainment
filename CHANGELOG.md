# Changelog

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
