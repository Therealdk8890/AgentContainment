"""Tamper-evident proof receipts for containment events.

The receipt format is intentionally small, canonical, and dependency-free.
HMAC authentication is used so an offline verifier can detect modifications
without trusting the receipt transport or storage layer.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import uuid
from dataclasses import dataclass
from typing import Any


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class ProofReceipt:
    """An authenticated, canonically serialized containment proof."""

    payload: dict[str, Any]
    digest: str
    signature: str

    @classmethod
    def issue(cls, payload: dict[str, Any], secret: bytes) -> "ProofReceipt":
        if not isinstance(payload, dict) or not payload:
            raise ValueError("receipt payload must be a non-empty mapping")
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("receipt signing secret must be non-empty bytes")

        payload = dict(payload)
        payload.setdefault("receipt_id", str(uuid.uuid4()))
        canonical = _canonical(payload)
        digest = hashlib.sha256(canonical).hexdigest()
        signature = hmac.new(secret, canonical, hashlib.sha256).hexdigest()
        return cls(payload, digest, signature)

    def verify(self, secret: bytes) -> bool:
        if not isinstance(secret, bytes) or not secret:
            return False
        canonical = _canonical(self.payload)
        expected_digest = hashlib.sha256(canonical).hexdigest()
        expected_signature = hmac.new(
            secret, canonical, hashlib.sha256
        ).hexdigest()
        return (
            hmac.compare_digest(self.digest, expected_digest)
            and hmac.compare_digest(self.signature, expected_signature)
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "payload": dict(self.payload),
            "digest": self.digest,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, document: dict[str, Any]) -> "ProofReceipt":
        if not isinstance(document, dict):
            raise ValueError("receipt must be a mapping")
        required = {"payload", "digest", "signature"}
        if set(document) != required:
            raise ValueError("receipt has an invalid envelope")
        payload = document["payload"]
        digest = document["digest"]
        signature = document["signature"]
        if not isinstance(payload, dict):
            raise ValueError("receipt payload must be a mapping")
        if not isinstance(digest, str) or not digest:
            raise ValueError("receipt digest is invalid")
        if not isinstance(signature, str) or not signature:
            raise ValueError("receipt signature is invalid")
        return cls(dict(payload), digest, signature)


class ReceiptVerifier:
    """Offline verifier with optional replay detection."""

    def __init__(self, secret: bytes):
        if not isinstance(secret, bytes) or not secret:
            raise ValueError("receipt verification secret must be non-empty bytes")
        self._secret = secret
        self._seen_ids: set[str] = set()

    def verify(self, receipt: ProofReceipt, *, reject_replay: bool = True) -> bool:
        if not receipt.verify(self._secret):
            return False
        receipt_id = receipt.payload.get("receipt_id")
        if reject_replay and receipt_id is not None:
            if not isinstance(receipt_id, str) or not receipt_id:
                return False
            if receipt_id in self._seen_ids:
                return False
            self._seen_ids.add(receipt_id)
        return True
