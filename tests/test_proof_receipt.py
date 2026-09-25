import copy
import json

import pytest

from agent_containment.proof_receipt import ProofReceipt, ReceiptVerifier


SECRET = b"test-receipt-secret"
PAYLOAD = {
    "schema_version": 1,
    "receipt_id": "receipt-001",
    "execution_id": "exec-001",
    "agent_id": "agent-1",
    "epoch": 7,
    "containment": {
        "requested": True,
        "enforced": True,
        "independently_verified": True,
    },
    "adversarial_events": ["stale_epoch_rejected", "egress_denied"],
    "proof_status": "verified",
}


def test_receipt_round_trips_and_verifies_offline():
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)
    document = json.loads(json.dumps(receipt.to_dict()))
    restored = ProofReceipt.from_dict(document)

    assert restored.verify(SECRET)
    assert ReceiptVerifier(SECRET).verify(restored)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p.__setitem__("epoch", 8),
        lambda p: p.__setitem__("agent_id", "other-agent"),
        lambda p: p["adversarial_events"].append("controller_killed"),
        lambda p: p.__setitem__("proof_status", "verified-but-altered"),
    ],
)
def test_receipt_detects_payload_tampering(mutation):
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)
    tampered = copy.deepcopy(receipt.payload)
    mutation(tampered)
    forged = ProofReceipt(tampered, receipt.digest, receipt.signature)

    assert not forged.verify(SECRET)
    assert not ReceiptVerifier(SECRET).verify(forged)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda p: p["adversarial_events"].pop(0),
        lambda p: p["adversarial_events"].reverse(),
        lambda p: p["adversarial_events"].insert(0, "fake_event"),
    ],
)
def test_receipt_detects_event_sequence_tampering(mutation):
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)
    tampered = copy.deepcopy(receipt.payload)
    mutation(tampered)
    forged = ProofReceipt(tampered, receipt.digest, receipt.signature)

    assert not forged.verify(SECRET)


def test_receipt_detects_digest_or_signature_tampering():
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)

    bad_digest = ProofReceipt(receipt.payload, "0" * 64, receipt.signature)
    bad_signature = ProofReceipt(receipt.payload, receipt.digest, "0" * 64)

    assert not bad_digest.verify(SECRET)
    assert not bad_signature.verify(SECRET)


def test_canonicalization_makes_key_order_irrelevant():
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)
    reordered = dict(reversed(list(PAYLOAD.items())))
    equivalent = ProofReceipt(reordered, receipt.digest, receipt.signature)

    assert equivalent.verify(SECRET)


def test_truncated_or_extra_envelope_fields_are_rejected():
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)
    document = receipt.to_dict()

    truncated = dict(document)
    del truncated["signature"]
    with pytest.raises(ValueError):
        ProofReceipt.from_dict(truncated)

    extra = dict(document)
    extra["unexpected"] = True
    with pytest.raises(ValueError):
        ProofReceipt.from_dict(extra)


def test_replay_is_rejected_by_stateful_offline_verifier():
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)
    verifier = ReceiptVerifier(SECRET)

    assert verifier.verify(receipt)
    assert not verifier.verify(receipt)


def test_wrong_secret_cannot_verify_receipt():
    receipt = ProofReceipt.issue(PAYLOAD, SECRET)

    assert not receipt.verify(b"wrong-secret")
    assert not ReceiptVerifier(b"wrong-secret").verify(receipt)
