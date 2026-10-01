from agent_containment.destination_egress import parse_destination
from agent_containment.destination_binding import (
    DestinationBindingContext,
    DestinationBindingEvidence,
)


def test_destination_binding_context_preserves_authority_scope():
    context = DestinationBindingContext(
        policy_id="policy-1",
        policy_digest="sha256:policy",
        agent_id="agent-1",
        runtime_id="runtime-1",
        epoch=7,
        destinations=(parse_destination("api.example.com:443"),),
    )

    assert context.policy_id == "policy-1"
    assert context.policy_digest == "sha256:policy"
    assert context.agent_id == "agent-1"
    assert context.runtime_id == "runtime-1"
    assert context.epoch == 7
    assert context.destinations[0].host == "api.example.com"
    assert context.destinations[0].port == 443


def test_destination_binding_evidence_requires_explicit_verification_state():
    evidence = DestinationBindingEvidence(
        provider="example-provider",
        provider_version="1",
        effective_config_digest="sha256:effective",
        verification_method="live-state",
        verified=True,
    )

    assert evidence.verified is True
    assert evidence.effective_config_digest == "sha256:effective"