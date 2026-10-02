# Security Policy

## Supported Versions

Security fixes are currently provided for the latest published release and the current `main` branch.

| Version | Supported |
| --- | --- |
| Latest release | Yes |
| `main` | Yes |
| Older releases | No |

Because AgentContainment is an early research/prototype project, users should pin the version or commit they deploy and validate the privileged Linux enforcement path against their own host and kernel configuration.

## Reporting a Vulnerability

Please do **not** open a public GitHub issue for a suspected security vulnerability.

Use GitHub's private vulnerability reporting feature for this repository when available. If private reporting is unavailable, contact the project maintainer through the private contact mechanism associated with the GitHub repository and include:

- a concise description of the vulnerability;
- affected versions or commits;
- the security boundary or invariant that is affected;
- minimal reproduction steps or a proof of concept, when safe to provide;
- the expected versus observed behavior;
- any relevant host, kernel, runtime, or privilege assumptions.

Please avoid including secrets, credentials, personal data, or information that could enable exploitation of third-party systems.

## Scope

Security reports are especially valuable for issues affecting:

- controller/agent isolation;
- cgroup-v2 containment;
- eBPF egress enforcement;
- authorization and execution-epoch fencing;
- credential or capability revocation;
- recovery and fail-closed behavior;
- evidence integrity or verification-state confusion;
- privilege-boundary or Unix-socket authorization failures;
- concurrency or TOCTOU conditions that can bypass containment.

Reports should distinguish a defect in AgentContainment from a limitation of an external provider, kernel, host configuration, or deployment environment.

## Disclosure

Please allow reasonable time for investigation and remediation before public disclosure. Coordinated disclosure is preferred.

AgentContainment is not currently offered with a commercial security SLA or guaranteed response time.
