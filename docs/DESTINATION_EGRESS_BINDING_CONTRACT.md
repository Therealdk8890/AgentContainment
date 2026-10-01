# Destination Egress Binding Contract

AgentContainment currently provides application-level egress leases and provider-owned
deny-all containment. This contract defines the minimum boundary for a future provider
that enforces host:port destination allowlists.

This document does not claim that the current eBPF or Cilium providers implement
destination allowlisting.

## Security invariant

> A destination allowlist is enforceable only when the provider installs and independently
> verifies an effective rule set bound to the accepted policy identity, execution identity,
> runtime, and execution epoch.

A provider MUST fail closed when it cannot represent, install, or verify the requested
allowlist without widening it.

## 1. Policy input

The portable input is a sequence of entries with the form host:port.
- host is a DNS hostname or an IP address.
- port is decimal TCP/UDP port 1 through 65535.
- The policy field does not currently encode protocol.
- Entries are policy inputs, not resolved network state.
- Empty entries mean no destination binding is required by this contract.

The provider MUST reject malformed entries rather than normalize them into a broader destination.
The provider MUST NOT add wildcard, CIDR, URL-path, proxy, service-discovery, or application-layer semantics implicitly.

## 2. Resolution and protocol semantics

A provider implementing this contract MUST document:
- whether DNS names are resolved at bind time, continuously, or both;
- which address families are enforced;
- how multiple A/AAAA results are represented;
- how DNS failure is handled;
- whether TCP, UDP, or both are enforced;
- how protocol-specific behavior is represented when the portable policy has no protocol field.

A provider MUST NOT claim a hostname restriction when its effective rule set permits a broader destination than the resolved policy semantics.
DNS resolution state MUST remain provider-owned state. It MUST NOT silently become part of the portable policy digest unless the policy model explicitly changes to make it so.

## 3. Binding inputs

The provider binding operation MUST receive, or derive from trusted controller state:
- accepted policy ID;
- canonical policy digest;
- execution identity;
- runtime ID;
- current execution epoch;
- requested allowed_egress entries;
- provider identity and configuration.

External authorization MUST NOT independently supply destination authority.
The provider MUST bind its effective configuration to the exact policy digest and runtime scope supplied by the controller.

## 4. Installation lifecycle

The provider owns:
1. translation from portable entries to provider-specific rules;
2. installation or replacement of the effective rule set;
3. removal of the rule set;
4. provider-specific runtime state;
5. provider-specific evidence.

Installation MUST be atomic from the provider's enforcement perspective: execution must not observe a partially installed rule set as the successful binding state.
If installation fails or cannot be proven complete, the controller MUST have no destination-enforcement evidence to consume.

## 5. Epoch fencing

A binding is valid only for its exact policy_digest + execution_identity + runtime_id + epoch.
Containment or halt advances the runtime epoch. A binding from the previous epoch MUST be treated as stale.
Recovery MUST NOT implicitly reuse an old destination binding. A new epoch requires a new provider binding and independent verification before execution authority is restored when the policy requires destination enforcement.
Provider updates and DNS refreshes MUST NOT widen an already accepted policy. If the provider cannot safely reconcile an update, it MUST fail closed rather than retain an ambiguous or broader effective rule set.

## 6. Independent verification

A provider MUST expose verification that inspects provider-owned live state rather than trusting the success response from installation.
Minimum verification evidence SHOULD identify:
- provider name and version;
- policy ID and canonical policy digest;
- execution identity;
- runtime ID;
- execution epoch;
- effective configuration digest;
- installation or reconciliation timestamp;
- verification timestamp;
- verification method and result;
- effective destination set or a provider-verifiable digest of it.

Verification MUST detect target drift. A valid provider object attached to the wrong runtime is not evidence of a valid binding.

## 7. TOCTOU and interleaving boundary

The destination binding path MUST preserve the existing AgentContainment epoch fence.
The critical sequence is: read accepted policy and epoch; resolve or translate destinations; install provider state; verify provider state; issue or restore execution authority.
Containment or halt may occur between these stages.
An implementation MUST NOT assume that checking the epoch before resolution is sufficient. The provider/controller must revalidate the binding epoch at the authoritative installation boundary.
Similarly, verification of an old epoch MUST NOT authorize execution after a newer containment transition.
The security model should exercise these interleavings deterministically before a real provider is introduced.

## 8. Failure behavior

The following conditions MUST fail closed for a binding-required execution:
- malformed destination;
- unsupported address family or protocol semantics;
- DNS resolution failure where resolution is required;
- inability to represent a destination without widening policy;
- installation failure;
- target/runtime mismatch;
- effective configuration mismatch;
- verification failure;
- epoch mismatch or stale binding.

A provider MUST NOT report ENFORCED solely because a configuration object was successfully submitted to an external API.

## 9. Explicitly deferred semantics

This contract does not define:
- wildcard hostnames;
- CIDR ranges;
- URL paths;
- proxy-mediated authorization;
- dynamic service discovery;
- application-layer protocol inspection;
- provider-specific configuration formats;
- DNS pinning policy across future resolutions.

## 10. Relationship to containment

Destination allowlisting is not a replacement for emergency containment.
Containment remains capable of establishing a deny-all boundary. A destination provider may be active during execution, but containment MUST remain authoritative when the runtime enters the contained state.

The provider proves what it installed and where. AgentContainment owns the runtime lifecycle and epoch authority. WarrantKit owns the higher-level policy identity and composition.
