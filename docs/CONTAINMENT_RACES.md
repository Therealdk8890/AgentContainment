# Containment Races and Credential Revocation

Containment has to defend against time-of-check/time-of-use races.

A naive implementation can do this:

1. authorize an action
2. containment fires
3. credentials are revoked
4. the already-authorized action executes

AgentContainment uses **execution epochs and leases** as an in-process reference mechanism.

## Execution lease

An active runtime can issue a short-lived `ExecutionLease` containing the runtime epoch.

Containment or halt increments that epoch. Any lease issued before the state transition becomes invalid.

The gateway's side-effect paths are fenced in three stages:

1. acquire an epoch-bound execution lease
2. evaluate the policy authorization
3. route the final side-effect start through the atomic `Runtime.execute_if_active()` gate

The atomic gate validates the lease and active runtime state while holding the runtime lock, then invokes the modeled executor before releasing that lock. This closes the TOCTOU window between the final validation and invocation: containment or halt cannot advance the runtime epoch between those two operations.

The gateway applies this boundary to all three execution paths:

- `execute_with_lease()`
- `execute_egress()`
- the convenience `execute()` path

This is stronger than performing a second `lease_valid()` check immediately before calling the executor. A check followed by a separate call still leaves a race window; `execute_if_active()` makes the modeled side-effect start one atomic operation with respect to the runtime state transition.

The boundary is intentionally limited. Holding the runtime lock proves that the modeled side effect was not **started through the gateway** after the lease was invalidated. It does not cancel an external operation that was already started, nor does it make an abstract in-process executor equivalent to provider- or kernel-enforced revocation. Production adapters must provide the corresponding real enforcement at the side-effect boundary—for example cancellation/revocation semantics, network policy, process/container controls, or provider-specific credential invalidation.

## Credential lease

`CredentialStore` provides the same invalidation pattern for credentials. Revocation removes the credential and increments its credential epoch, invalidating previously issued leases.

This is deliberately an abstract model. Production integrations must enforce the equivalent property at the actual side-effect boundary—for example through IAM/session revocation, network policy, process/container controls, or provider-specific credential invalidation.

## Security property

The important property is not merely "we called revoke."

It is:

> A credential or execution authority issued before containment cannot authorize a new side effect after containment.

For execution authority, the gateway TOCTOU regression tests exercise the critical interleaving: containment advances the runtime epoch at the atomic execution boundary, and the executor must not run.

The implementation should continue to be tested under concurrency and failure injection as the real adapters are added.
