# Architecture

AgentContainment is organized around an out-of-band enforcement point.

1. **Agent** requests an action.
2. **ActionGateway** is the enforcement boundary.
3. **PolicyEngine** makes deterministic authorization decisions.
4. **Runtime** tracks whether execution is active, halted, or contained.
5. **ContainmentController** has authority to halt execution and revoke capabilities.
6. **ResourceGraph** records the potential blast radius.
7. **Incident evidence** produces a deterministic SHA-256 digest over the recorded event set.

The prototype intentionally uses simulated capabilities and resources. Production adapters will need real process isolation, credential revocation, network controls, and provider-specific integrations.
