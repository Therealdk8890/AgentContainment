# Bootstrap and Admission Security

## Purpose

Controller isolation is only meaningful if an untrusted agent cannot prevent the
controller from starting, tamper with the controller before startup, or start
without the controller when the deployment requires controller-mediated
containment.

The bootstrap trust chain is:

```text
trusted host/image
      ↓
service-manager policy
      ↓
controller executable + configuration
      ↓
controller process
      ↓
agent safety floor
      ↓
agent admission
```

The agent is admitted only after the trusted launcher has established the
controller boundary.

## Required deployment boundary

The controller service must be owned by a dedicated service identity and
protected from the agent workload:

- controller executable, Python environment, configuration, and service unit
  are not writable by the agent;
- the controller runs under a dedicated UID/GID distinct from the agent;
- the controller socket directory is controller-owned and not writable by the agent;
- the controller has an independent cgroup and lifecycle;
- the agent cannot invoke or modify the service manager;
- the agent cannot replace the controller executable or its dependencies;
- the agent cannot modify controller configuration before startup;
- the agent receives no admission path that bypasses the controller when the
  deployment requires controller mediation.

The reference systemd unit establishes the service-manager portion of this
model. It is a deployment reference, not a claim that every host is hardened
merely by copying the file.

## Fail-closed admission

`agent_containment.bootstrap.require_controller_available()` is a small
launcher-facing check. It refuses admission if the controller socket is
missing or unreachable.

This check is not itself a security boundary if the agent can choose whether
to call it. The trusted service manager, container runtime, or equivalent
orchestrator must own the actual admission decision.

## Static trust before startup

The deployment process should establish, before any agent workload is admitted:

1. controller executable/interpreter and dependencies are trusted and
   administrator-owned;
2. controller configuration is trusted and not agent-writable;
3. service-manager unit is trusted and not agent-writable;
4. controller runtime directory is trusted and not agent-writable;
5. controller and agent identities are distinct;
6. controller and agent cgroups are distinct;
7. controller availability is established before agent admission;
8. controller restart cannot silently grant the agent new authority.

The controller must not be responsible for proving the trustworthiness of its
own executable. File ownership, integrity measurement, image provenance, and
boot-chain attestation belong to the host provisioning or orchestration layer.

## Failure semantics

If controller startup fails, the safe deployment behavior is:

```text
controller unavailable
       ↓
NO AGENT ADMISSION
```

If the controller restarts, previously contained state remains an admission
fence; recovery must remain controller-authorized.

## What is proven vs deployment-dependent

Repository tests prove the application-level availability check. The trusted
Linux integration path proves process/cgroup/IPC isolation after startup.

Host-specific claims about package ownership, filesystem integrity, service
manager databases, boot chains, container images, or measured boot require
deployment attestation and are intentionally not claimed as repository proofs.

## Acceptance criterion

> If the trusted controller is unavailable or its trusted startup boundary is
> not established, the agent workload is not admitted.
