# AgentContainment

**Runtime containment and incident response for autonomous AI agents.**

AgentContainment is a framework-agnostic control plane designed to intercept agent actions, enforce policy, halt compromised runs, revoke authority, contain blast radius, and preserve verifiable incident evidence.

## Core model

`Detect → Prove → Halt → Contain → Map → Recover`

The containment plane is designed to sit **outside the agent's trust boundary**. An agent must not control its own kill switch, containment policy, credentials, or incident evidence.

## Status

Early research/prototype. The current implementation focuses on deterministic action interception, policy decisions, runtime state, containment, child-agent propagation, blast-radius tracking, and incident records.

## Design goals

- Fail closed for explicitly denied actions.
- Keep containment authority outside the agent.
- Make every action observable and attributable.
- Make incident state machine-driven and testable.
- Separate detection/policy from enforcement.
- Support reversible recovery without pretending all side effects are reversible.
- Provide an integration point for DProvenanceKit.

## Repository layout

- `src/agent_containment/` — core library
- `policies/` — example policy
- `demo/` — controlled rogue-agent demonstration
- `tests/` — security and behavior tests
- `docs/` — architecture, threat model, and adversarial containment notes

## Safety

The demo uses a simulated environment. It does not execute destructive actions against real infrastructure.

## License

Apache-2.0
