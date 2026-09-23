# Containment Races and Credential Revocation

Containment has to defend against time-of-check/time-of-use races.

A naive implementation can do this:

1. authorize an action
2. containment fires
3. credentials are revoked
4. the already-authorized action executes

AgentContainment now uses **execution epochs and leases** as an in-process reference mechanism.

## Execution lease

An active runtime can issue a short-lived `ExecutionLease` containing the runtime epoch.

Containment or halt increments that epoch. Any lease issued before the state transition becomes invalid.

The gateway checks the lease:

- before authorization
- after authorization
- immediately before the modeled side effect

This prevents a stale authorization lease from being treated as valid after a containment transition.

## Credential lease

`CredentialStore` provides the same invalidation pattern for credentials. Revocation removes the credential and increments its credential epoch, invalidating previously issued leases.

This is deliberately an abstract model. Production integrations must enforce the equivalent property at the actual side-effect boundary—for example through IAM/session revocation, network policy, process/container controls, or provider-specific credential invalidation.

## Security property

The important property is not merely "we called revoke."

It is:

> A credential or execution authority issued before containment cannot authorize a new side effect after containment.

The implementation should be tested under concurrency and failure injection as the real adapters are added.
