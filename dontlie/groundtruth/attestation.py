"""Route-attestation API: bind a receipt to a blind-probe result.

A ``RouteAttestation`` is a signed claim that a particular ``Receipt``
was the result of a route that produced the same ``provider``/``model``
as a separate blind probe. It is signed by the operator's own key
(not the witness's) so verifiers can cross-check it against the
receipts they hold in the local vault.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, replace
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .helpers import short_nonce
from .probe import BlindProbeResult


class RouteMismatchError(Exception):
    """Raised when a route attestation does not match the receipt/probe."""


@dataclass
class RouteAttestation:
    receipt_id: int
    payload_sha256: str
    provider: str
    model: str
    correlation_id: str
    witness_key_id: str
    operator_key_id: str
    signature: str
    elapsed_ms: int = 0
    nonce: str = field(default_factory=short_nonce)


def _sign_payload(payload: bytes, private_key) -> str:  # Ed25519PrivateKey
    return private_key.sign(payload).hex()


def _canonical_attestation_payload(att: RouteAttestation, *, for_signing: bool) -> bytes:
    body = {
        "receipt_id": att.receipt_id,
        "payload_sha256": att.payload_sha256,
        "provider": att.provider,
        "model": att.model,
        "correlation_id": att.correlation_id,
        "witness_key_id": att.witness_key_id,
        "operator_key_id": att.operator_key_id,
        "elapsed_ms": att.elapsed_ms,
        "nonce": att.nonce,
    }
    if not for_signing:
        body["signature"] = att.signature
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def attest_receipt(
    receipt: dict,
    probe: BlindProbeResult,
    *,
    operator_key_pair: Any,
    witness_key_id: str = "witness-self",
) -> RouteAttestation:
    """Sign a route attestation linking ``receipt`` to ``probe``."""
    if not hasattr(operator_key_pair, "private") or not hasattr(operator_key_pair, "public"):
        raise TypeError("operator_key_pair must expose .private and .public")
    att = RouteAttestation(
        receipt_id=receipt["id"],
        payload_sha256=receipt["payload_sha256"],
        provider=probe.provider,
        model=probe.model,
        correlation_id=probe.correlation_id,
        witness_key_id=witness_key_id,
        operator_key_id=getattr(operator_key_pair, "key_id", ""),
        signature="",
        elapsed_ms=probe.elapsed_ms,
    )
    payload = _canonical_attestation_payload(att, for_signing=True)
    att = replace(att, signature=_sign_payload(payload, operator_key_pair.private))
    return att


def verify_route_attestation(
    attestation: RouteAttestation,
    receipt: dict,
    probe: BlindProbeResult,
    *,
    operator_public_key: Ed25519PublicKey,
) -> bool:
    """Verify a route attestation; raise RouteMismatchError on inconsistency."""
    if attestation.receipt_id != receipt["id"]:
        raise RouteMismatchError("attestation.receipt_id != receipt.id")
    if attestation.payload_sha256 != receipt["payload_sha256"]:
        raise RouteMismatchError("attestation.payload_sha256 != receipt.payload_sha256")
    if attestation.provider != probe.provider:
        raise RouteMismatchError("attestation.provider != probe.provider")
    if attestation.model != probe.model:
        raise RouteMismatchError("attestation.model != probe.model")
    if attestation.correlation_id != probe.correlation_id:
        raise RouteMismatchError("attestation.correlation_id != probe.correlation_id")
    payload = _canonical_attestation_payload(attestation, for_signing=True)
    try:
        operator_public_key.verify(bytes.fromhex(attestation.signature), payload)
    except (InvalidSignature, ValueError) as exc:
        raise RouteMismatchError(f"signature invalid: {exc}") from exc
    return True


__all__ = [
    "RouteAttestation",
    "RouteMismatchError",
    "attest_receipt",
    "verify_route_attestation",
]
