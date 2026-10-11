# Concurrent Runtime Execution: Design Gate

## Status

**Proposal only.** This document does not change runtime behavior and is not evidence that concurrent execution is implemented or safe.

## Why this is being considered

`Runtime.execute_if_active()` currently validates the epoch-bound lease and invokes the executor while holding the runtime `RLock`. That makes the validation-to-callback-start boundary atomic with respect to `halt()` and `contain()`, but it also serializes callbacks sharing one runtime for the full callback duration.

Removing the lock around the callback without replacing that boundary would reintroduce a time-of-check/time-of-use race. A thread could validate an old lease, lose the lock to containment, and then start a side effect after the runtime epoch changed.

## Required invariants

Any concurrent execution implementation must preserve all of these properties:

1. **Atomic admission:** checking runtime state and lease epoch and registering an operation as in-flight happen under one lock.
2. **Close admission first:** halt/contain atomically changes state and advances the epoch before waiting for existing operations. No new operation using the old epoch may be admitted after that transition.
3. **Explicit drain semantics:** distinguish “authority has been revoked / new work is fenced” from “all previously admitted callbacks have returned.” Neither state nor receipt text may imply that a running external request was cancelled.
4. **Failure-safe accounting:** every admitted operation decrements the in-flight count in a `finally` path, including when the callback raises.
5. **Reentrancy is specified:** a callback that requests halt/contain must not deadlock waiting for itself. Concurrent callbacks requesting halt must not wait on each other in a cycle.
6. **No false cancellation claim:** a runtime lock or drain barrier cannot cancel a provider request, remote API call, or network operation already started. Adapter-specific cancellation/revocation remains separate.
7. **Recovery remains fenced:** recovery may issue a new epoch only after the containment transaction's existing durability and authorization checks; old leases stay invalid.

## Candidate API shape (not approved)

A possible split is:

- `begin_execution(lease)`: atomically validate the lease and register an in-flight operation; return a scoped operation token or reject.
- `finish_execution(token)`: idempotently unregister the operation in a `finally` block.
- `request_halt()`: synchronously close admission and advance the epoch, but do not claim in-flight work has drained.
- `halt_and_drain(timeout=None)`: close admission and wait for previously admitted callbacks to return, with an explicit timeout/failure result.
- Keep `execute_if_active()` as the existing atomic serial primitive until gateway migration and compatibility are reviewed.

This is only a candidate. Introducing a split between request and drain changes what callers may infer from a method named `halt()`. The API names, timeout behavior, report/receipt semantics, and compatibility strategy need review before implementation.

## Reentrancy and concurrency cases that must be decided

- A callback calls `halt()` or containment synchronously from inside its own execution.
- Two in-flight callbacks concurrently request halt.
- One callback requests containment while another callback remains blocked.
- An in-flight callback raises, times out, or never returns.
- A drain timeout expires: runtime must remain non-executable, and callers must not interpret timeout as proof that all work stopped.
- A callback attempts nested execution under the same runtime.
- Recovery races with a pending drain or a second containment request.
- A callback has already started a remote side effect that cannot be cancelled by the local runtime.

## Required tests before any gateway adopts the protocol

Use events/barriers, not sleeps, to establish ordering. Tests must prove:

1. Multiple admitted callbacks can overlap under one runtime.
2. A halt transition rejects all later admissions, including old-epoch leases.
3. A halt/drain caller cannot report successful drain while an admitted callback is blocked.
4. Releasing the blocked callback allows drain to complete and the in-flight count returns to zero.
5. Callback exceptions still release their in-flight registration.
6. Callback-triggered containment does not deadlock.
7. Two simultaneous halt requests do not deadlock or double-advance state unexpectedly.
8. Drain timeout leaves the runtime fenced and explicitly reports that draining is incomplete.
9. No test describes an already-started external side effect as cancelled unless the adapter proves cancellation independently.
10. Existing lease, TOCTOU, egress, epoch, recovery, and receipt tests continue to pass.

## Measurement gate

After correctness tests pass, compare direct tool calls, the current serial gate, and the candidate concurrent gate on the same host and workload. Report throughput and p50/p95/p99 over repeated rounds, plus concurrency and callback-duration distributions. Include both a no-op callback and representative blocking/I/O callbacks. Treat noisy microbenchmark tails as directional, not production SLOs.

## Recommendation

Do not replace the current lock scope in a performance-only patch. First agree on the distinction between **admission closed**, **runtime contained**, and **in-flight work drained**. Implement behind a separate API or feature boundary, keep the current safe primitive as the default, and only migrate the gateway after the adversarial tests and benchmark are independently reviewed.
