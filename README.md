# AgentContainment

**Runtime containment and enforcement primitives for AI agents.**

[![PyPI](https://img.shields.io/pypi/v/agentcontainment?label=PyPI)](https://pypi.org/project/agentcontainment/)
[![Python](https://img.shields.io/pypi/pyversions/agentcontainment?label=Python)](https://pypi.org/project/agentcontainment/)
[![License](https://img.shields.io/github/license/Therealdk8890/AgentContainment)](https://github.com/Therealdk8890/AgentContainment/blob/main/LICENSE)

> **Status: Early research/prototype — not production ready.**

AgentContainment is a controller-side security layer for AI agents. It is designed for the moment when an agent can no longer be trusted to enforce its own boundaries.

The core idea is simple:

> **Don't ask the agent to obey the boundary. Put the boundary outside the agent — then verify that it was enforced.**

AgentContainment separates **agent intent**, **controller authority**, **external enforcement**, and **incident evidence** so that no single compromised agent process is trusted to authorize, contain, recover, or rewrite its own security state.

## At a glance

~~~
                         AGENT
                           │
                           │ request action
                           ▼
                 ┌─────────────────────┐
                 │  AGENTCONTAINMENT   │
                 │   CONTROL PLANE     │
                 │                     │
                 │ authorize           │
                 │ fence / revoke      │
                 │ contain / recover   │
                 │ record evidence     │
                 └──────────┬──────────┘
                            │
                 enforce → verify → certify
                            │
              ┌─────────────┼─────────────┐
              ▼             ▼             ▼
          cgroup v2       eBPF         Cilium /
          process       egress        Tetragon
          boundary      boundary      integrations
              └─────────────┼─────────────┘
                            ▼
                    EXTERNAL BOUNDARY
                            │
                            ▼
                     VERIFIED STATE
                            │
                            ▼
                    AUDIT / EVIDENCE
                            │
                            ▼
                         WARDEN
                    read-only observer
~~~

The controller owns the containment decision and recovery authority. Enforcement is delegated to independently verifiable mechanisms rather than being treated as a property of the agent's prompt, framework, or tool wrapper.

## Why it exists

Traditional agent guardrails often live inside the application executing the agent. That creates a difficult security question:

**What happens when the agent itself becomes untrusted?**

AgentContainment is built around a different trust boundary:

~~~
Agent requests
      │
      ▼
Controller authorizes
      │
      ▼
External mechanism enforces
      │
      ▼
Independent verification
      │
      ▼
Controller-owned evidence
      │
      ▼
Warden observes
~~~

The project is deliberately concerned with the distinction between **asking an agent to stop** and **having an independent mechanism capable of stopping it**.

## Core security model

AgentContainment follows:

**Detect → Prove → Halt → Contain → Map → Recover**

The containment plane is designed to remain outside the agent's trust boundary.

### Controller authority

The controller owns:

- action authorization;
- stateful policy history;
- admission and epoch fencing;
- capability revocation;
- containment and recovery decisions;
- enforcement verification state;
- controller-owned audit evidence.

An agent does **not** receive authority over its own kill switch, containment policy, controller credentials, or incident evidence.

### Defense in depth

No single mechanism is treated as sufficient:

1. **Action authorization** — deterministic decisions before tool execution.
2. **Stateful policy** — action history can detect dangerous sequences.
3. **Epoch fencing** — containment invalidates outstanding execution and egress leases.
4. **Capability revocation** — application-level authority is revoked during containment.
5. **Process containment** — Linux cgroup v2 can terminate the contained cgroup.
6. **Kernel egress enforcement** — the Linux eBPF integration can block outbound packets.
7. **Tamper-evident evidence** — controller-owned audit events are linked in a hash chain.

## What is actually enforced?

AgentContainment uses a provider-neutral enforcement contract.

~~~
                 REQUEST CONTAINMENT
                          │
                          ▼
                     ENFORCE
                          │
                          ▼
                     VERIFY
                          │
                          ▼
                 CERTIFY CONTAINED
~~~

A provider is not considered successful merely because a command or API request was accepted. Providers report explicit states such as:

- ENFORCED
- VERIFICATION_FAILED
- DEGRADED
- NOT_CONFIGURED

Current and planned enforcement targets include:

| Provider | Boundary | Role |
|---|---|---|
| **cgroup v2** | Process / workload | Linux process containment |
| **eBPF** | Network egress | Kernel-level egress enforcement |
| **Cilium** | Kubernetes network | Optional network enforcement integration |
| **Tetragon** | Runtime / kernel | Optional runtime enforcement integration |

Cilium and Tetragon are **optional integration targets**, not dependencies of the core package.

## Stateful policy

Policies can reason about sequences rather than isolated actions.

~~~python
from agent_containment.policy import PolicyEngine, SequenceRule

policy = PolicyEngine(sequence_rules=[
    SequenceRule(
        "prevent-download-upload-delete",
        ("download_file", "upload_file", "delete_file"),
    )
])
~~~

The controller can allow:

~~~
download_file → ALLOW
upload_file   → ALLOW
~~~

and halt the third action:

~~~
delete_file → HALT
~~~

The policy history belongs to the controller rather than being supplied by the agent.

## Standalone control plane

The repository includes a Unix-domain control transport that separates the agent from the controller process.

~~~
Agent
  │
  │ Unix-domain socket
  ▼
agentcontainmentd
  │
  ├── peer-credential authorization
  ├── action policy
  ├── stateful policy history
  ├── containment authority
  └── audit / evidence
  │
  ▼
OS enforcement boundary
  ├── cgroup v2
  └── eBPF cgroup egress enforcement
~~~

The daemon exposes a deliberately narrow control protocol for registration, authorization, status, containment, reports, and snapshots.

## Linux enforcement

On Linux, a workload can be placed in a dedicated cgroup v2.

Containment can then:

- invalidate application and egress leases;
- revoke application capabilities;
- activate the eBPF egress blocker;
- terminate the contained cgroup;
- preserve controller-owned evidence and telemetry paths.

The cgroup provider uses cgroup.kill for containment and verifies state through cgroup.events. Configured cgroups are identity-bound so a deleted-and-recreated path is not silently accepted as the original workload boundary.

**Important:** this is not a claim that the Python control plane alone provides kernel-level isolation. Production deployments must provision and protect the cgroup hierarchy outside the agent trust boundary and validate the privileged integration on the target host.

See:

- docs/OS_LEVEL_CONTAINMENT.md
- docs/EGRESS_CONTAINMENT.md

## Warden: eyes, not hands

Warden is the observation boundary above the control path.

> **Warden gets eyes, not hands.**

Warden can observe and display the governance chain, but it does not:

- authorize actions;
- contain agents;
- release containment;
- mutate enforcement state;
- approve recovery.

The intended chain is:

~~~
ACTION
  ↓
CLAIM VERIFICATION
  ↓
AUTHORIZATION
  ↓
EXTERNAL ENFORCEMENT
  ↓
EVIDENCE
  ↓
WARDEN OBSERVATION
~~~

The security invariant is:

> **Warden observation must be incapable of changing authorization or containment state.**

See docs/MILESTONE_8_WARDEN.md.

## Governance stack

AgentContainment is designed to compose with adjacent governance layers rather than replace them.

~~~
                  AI GOVERNANCE STACK

        ┌──────────────────┐
        │  DProvenanceKit  │
        │      PROVE       │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │ AgentContainment │
        │     CONTROL      │
        └────────┬─────────┘
                 │
                 ▼
        ┌──────────────────┐
        │  ClaimProofKit   │
        │      VERIFY      │
        └────────┬─────────┘
                 │
                 ▼
          REGRESSION GATE
                 │
                 ▼
              INCIDENT
                 │
                 └──────► evidence / future tests
~~~

The broader governance loop is:

**Observe → Prove → Authorize → Enforce → Contain → Recover → Regression**

The projects have deliberately separate responsibilities:

- **DProvenanceKit** — reconstructs and proves what happened.
- **AgentContainment** — controls what is allowed and what happens when containment is required.
- **ClaimProofKit** — verifies whether claims are supported by evidence.
- **Warden** — provides read-only observation.

No component is intended to quietly impersonate another component's authority.

## Audit evidence

The controller can maintain a JSONL hash chain linking each event to the previous event.

Verification can detect:

- edits;
- deletion;
- reordering of the recorded chain.

This is **tamper-evident**, not immutable storage. An attacker who can rewrite both the audit file and its trusted reference can rewrite the evidence. External anchoring remains a future hardening layer.

## Agent hierarchy

AgentTree models parent/child agents and propagates containment through currently registered descendants.

Child capabilities are attenuated to the intersection of the capabilities requested by the child and held by the parent.

This provides a foundation for multi-agent containment without assuming that every child has the same authority as its parent.

## Installation

### PyPI

The first public release is now available:

~~~bash
python -m pip install agentcontainment
~~~

Verify the installed distribution:

~~~bash
python -c "from importlib.metadata import version; print(version('agentcontainment'))"
~~~

Expected:

~~~text
0.1.0
~~~

The core package has no third-party runtime dependencies.

Linux-specific enforcement providers may require host capabilities and external tooling such as eBPF/libbpf or Cilium/Kubernetes. Those are deployment requirements rather than core Python dependencies.

### Development install

~~~bash
git clone https://github.com/Therealdk8890/AgentContainment.git
cd AgentContainment
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e .
~~~

## Security and production scope

**AgentContainment 0.1.0 is an early research/prototype release. It is not a production-grade universal security boundary.**

The current release demonstrates concrete controller/enforcement boundaries, including real-host Linux/eBPF validation in the trusted CI path, but deployment guarantees depend on the environment.

Before production use, validate at minimum:

- host privileges;
- kernel and cgroup support;
- cgroup hierarchy ownership and protection;
- identity binding;
- policy coverage;
- enforcement configuration;
- recovery procedures;
- external side effects that cannot be reversed after execution.

AgentContainment does **not** claim that completed external side effects can be undone.

## Tests

The repository contains:

- unit and security tests under tests/;
- privileged Linux integration tests under tests/integration/;
- real-host enforcement validation for the Linux/eBPF path;
- regression fixtures for previously observed incidents;
- release-gate replay tests.

Privileged tests are opt-in and intended for isolated Linux environments.

## Repository layout

- src/agent_containment/ — core library and controller components
- ebpf/ — Linux eBPF enforcement program and controller
- policies/ — example policies
- demo/ — controlled rogue-agent demonstration
- tests/ — security and behavior tests
- tests/integration/ — opt-in privileged Linux integration tests
- docs/ — architecture, threat model, and containment notes
- scripts/ — build and development helpers

## Roadmap

The project is intentionally evolving toward a broader provider-neutral agent security control plane.

Near-term areas include:

- deeper enforcement-provider integrations;
- broader incident-to-regression workflows;
- stronger external evidence anchoring;
- deployment hardening and operational guidance;
- additional multi-agent containment scenarios.

## License

Apache-2.0
