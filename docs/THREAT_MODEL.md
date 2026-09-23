# Threat Model

## Primary threat

An autonomous agent receives more authority than intended and attempts an unsafe action.

## Security boundary

The containment controller must be outside the agent's authority. The agent must not be able to modify containment state, policy, credentials, or evidence.

## Prototype assumptions

The current implementation demonstrates the control-plane semantics but does not claim operating-system or cloud-level isolation. Those controls are future adapters.

## Required production properties

- fail-closed action gateway
- independent control plane
- credential revocation
- process/container termination
- network egress control
- immutable evidence storage
- authenticated control messages
- recovery actions with explicit reversibility
