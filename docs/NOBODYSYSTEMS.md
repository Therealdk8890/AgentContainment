# AgentContainment and NobodySystems: evaluation and commercial boundary

## What belongs in which layer?

| Product | Responsibility | Demonstrated scope | Not established |
|---|---|---|---|
| **AgentContainment** (this Apache-2.0 engine) | **Enforcement** | Controller-owned leases, local policy/containment lifecycle, Linux cgroup-v2/eBPF opt-in privileged proof, structured adversarial evidence | Universal isolation, protection from a compromised controller/host, or fleet-wide enterprise operations |
| [WarrantKit](https://github.com/Therealdk8890/WarrantKit) (Apache-2.0) | **Authority** | Signed runtime-scoped Warrants; epoch invalidation; protected adapter/gateway proof | Prevention of side effects that bypass the gateway |
| [DProvenanceKit](https://github.com/Therealdk8890/DProvenanceKit) (Apache-2.0) | **Evidence** | Instrumented decision-path traces, regression gating and offline-verifiable attestations | Correctness of every event or any permission to execute |
| **NobodySystems** (separate proprietary private alpha) | **Operational/control plane** | Constrained local controller, bounded guarded tools, operator interfaces, and separately executed evidence verifier | Production hostile-agent sandbox, general fleet management, enterprise SLA, or shipped hosted control plane |

**NobodySystems** is where organizational policy lifecycle/distribution, cross-engine evidence correlation, fleet operations, enterprise access/tenancy, deployment management, and commercial guarantees are intended to live. The current private-alpha package does **not** deliver those capabilities as production-ready services. Its operational layer must never move containment authority into the agent or weaken independent offline verification.

## Reproduce this engine's boundary first

Start from the documented [development installation](../README.md#development-install) on an **isolated Linux host**. The following privileged commands require root or suitable delegated cgroup/eBPF privileges and must not be run against production workloads:

```bash
bash scripts/build_ebpf.sh
AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1 python demo/hostile_agent_demo.py
```

Expected evidence includes test-linked proof IDs, peer/controller isolation checks, cgroup process termination, post-containment egress denial where configured, and stale-lease rejection. The runner should fail non-zero if a selected proof fails or its evidence is missing or mismatched. Keep `hostile-agent-evidence.json`, the exact source commit, test selection, kernel/cgroup/eBPF configuration, and verification outcome together. See [adversarial testing](ADVERSARIAL_TESTING.md), [security contract](SECURITY_CONTRACT.md), and [threat model](THREAT_MODEL.md).

A passing unprivileged `python -m pytest -q` run does **not** establish host enforcement. A valid HMAC receipt detects tampering to a verifier sharing the secret; it is **not** host attestation, asymmetric non-repudiation, or proof that every observed kernel claim is true. Evaluate recovery and failure cases separately, including degraded/not-configured providers.

## Requirements for a NobodySystems evaluation

1. Identify the specific adversarial agent actions and alternative side-effect/credential paths.
2. Pin AgentContainment, WarrantKit, evidence SDK, and NobodySystems alpha revisions; use a representative **sanitized** workload.
3. Verify deny-before-effect, stale authority, external process enforcement, trusted-key evidence verification, containment/recovery ordering, and missing-provider failure behavior at the **claimed** deployment boundary.
4. Collect independent verifier verdicts and explicit failures/open security gaps; a fixed Linux sleep-workload proof alone does not prove arbitrary hostile-code isolation.
5. Ask which organizational policy, evidence correlation, fleet, tenancy, support, and hosting claims are implemented versus contractual future roadmap before commercial use.

## Independent rights and private-alpha access

- AgentContainment, WarrantKit and DProvenanceKit retain separate open-source releases and Apache-2.0 licenses; their documented local security and evidence paths are not gated behind a NobodySystems subscription.
- NobodySystems proprietary source, access approval, evaluation terms, and future enterprise guarantees are separate. Private repository links will not work for unauthenticated evaluators.
- Local authority validation, containment, and independent verification must remain operable during management-plane outages; no dashboard or signature alone expands the enforced trust boundary.
- [Request a controlled NobodySystems private-alpha evaluation](mailto:danielpaulkissel@gmail.com?subject=NobodySystems%20private-alpha%20evaluation). Require a written supported threat model, pinned artifact set, verification procedure, limitations, and release blockers.

See the [governance-platform architecture](GOVERNANCE_PLATFORM.md) for planned integration ownership versus the implemented enforcement primitive.
