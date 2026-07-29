"""Wire format for the Don't-Lie peer-witness protocol.

Dataclasses + canonical JSON serialization + Ed25519 signing helpers.
This module is intentionally pure-Python with no network or storage I/O
so it can be unit-tested in isolation and reviewed in one sitting.

Design rules:
- Every signature is over the canonical JSON of the payload, with the
  signature field itself excluded from the signed bytes.
- Only SHA-256 digests and a short random nonce cross the witness
  boundary; prompts/responses never do.
- Timestamps are integers (epoch seconds) and `expires_at` is part of
  the signed payload to make replay attacks detectable.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .helpers import short_nonce


# --- request -----------------------------------------------------------------


@dataclass
class PeerWitnessRequest:
    """A request a witness is asked to corroborate.

    The witness will only ever see a request like this — never the
    underlying prompt or response. The only fields are digests, the
    operator's claimed provider/model, a short nonce, and an expiry.
    """

    receipt_payload_sha256: str
    provider: str
    model: str
    correlation_id: str
    nonce: str
    issued_at: int
    expires_at: int
    requester_key_id: str
    signature: str = ""

    def canonical(self) -> dict[str, Any]:
        return asdict(self)

    def is_expired(self, now: int | None = None) -> bool:
        return (now or int(time.time())) >= self.expires_at


# --- attestation -------------------------------------------------------------


@dataclass
class PeerWitnessAttestation:
    """A witness's signed statement that they observed a request."""

    request: PeerWitnessRequest
    receipt_payload_sha256: str
    provider: str
    model: str
    correlation_id: str
    nonce: str
    witness_key_id: str
    signature: str = ""
    observed_at: int = field(default_factory=lambda: int(time.time()))

    def canonical(self) -> dict[str, Any]:
        # Sign the request fields plus the witness's observed_at; the
        # nested `request` is canonicalized separately to keep the
        # signing surface flat and stable.
        return {
            "request": self.request.canonical(),
            "receipt_payload_sha256": self.receipt_payload_sha256,
            "provider": self.provider,
            "model": self.model,
            "correlation_id": self.correlation_id,
            "nonce": self.nonce,
            "witness_key_id": self.witness_key_id,
            "observed_at": self.observed_at,
            "signature": self.signature,
        }


# --- canonicalization + signing ---------------------------------------------


def _canonical(obj: dict[str, Any], *, exclude: tuple[str, ...] = ()) -> bytes:
    body = {k: v for k, v in obj.items() if k not in exclude}
    return json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")


def serialize_request(req: PeerWitnessRequest, *, for_signing: bool = False) -> bytes:
    """Stable JSON of the request. Excludes the signature field when signing."""
    exclude = ("signature",) if for_signing else ()
    return _canonical(req.canonical(), exclude=exclude)


def serialize_attestation(att: PeerWitnessAttestation, *, for_signing: bool = False) -> bytes:
    """Stable JSON of the attestation. Excludes the signature field when signing."""
    exclude = ("signature",) if for_signing else ()
    return _canonical(att.canonical(), exclude=exclude)


def _sign(payload: bytes, private_key: Ed25519PrivateKey) -> str:
    return private_key.sign(payload).hex()


def build_signed_request(
    *,
    receipt_payload_sha256: str,
    provider: str,
    model: str,
    correlation_id: str,
    nonce: str | None = None,
    ttl_seconds: int = 300,
    requester_key_id: str,
    requester_private_key: Ed25519PrivateKey,
    now: int | None = None,
) -> PeerWitnessRequest:
    """Build and sign a witness request.

    The requester signs the request so a witness can confirm the
    request came from the same operator who signed the receipt. The
    nonce is shared with the `RouteAttestation` claim so witnesses and
    operators bind to the same opaque token without coordination.
    """
    issued = int(now or time.time())
    req = PeerWitnessRequest(
        receipt_payload_sha256=receipt_payload_sha256,
        provider=provider,
        model=model,
        correlation_id=correlation_id,
        nonce=nonce or short_nonce(),
        issued_at=issued,
        expires_at=issued + ttl_seconds,
        requester_key_id=requester_key_id,
        signature="",
    )
    payload = serialize_request(req, for_signing=True)
    req.signature = _sign(payload, requester_private_key)
    return req


def deserialize_request(blob: bytes | str) -> PeerWitnessRequest:
    data = json.loads(blob)
    return PeerWitnessRequest(**data)


def deserialize_attestation(blob: bytes | str) -> PeerWitnessAttestation:
    data = json.loads(blob)
    req = PeerWitnessRequest(**data["request"])
    return PeerWitnessAttestation(request=req, **{k: v for k, v in data.items() if k != "request"})


def verify_request_signature(
    request: PeerWitnessRequest,
    requester_public_key: Ed25519PublicKey,
) -> bool:
    """Verify the requester's signature on the request payload."""
    if not request.signature:
        return False
    payload = serialize_request(request, for_signing=True)
    try:
        requester_public_key.verify(bytes.fromhex(request.signature), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


def verify_attestation_signature(
    attestation: PeerWitnessAttestation,
    witness_public_key: Ed25519PublicKey,
) -> bool:
    """Verify the witness's signature on the attestation payload."""
    if not attestation.signature:
        return False
    payload = serialize_attestation(attestation, for_signing=True)
    try:
        witness_public_key.verify(bytes.fromhex(attestation.signature), payload)
        return True
    except (InvalidSignature, ValueError):
        return False


__all__ = [
    "PeerWitnessRequest",
    "PeerWitnessAttestation",
    "build_signed_request",
    "serialize_request",
    "serialize_attestation",
    "deserialize_request",
    "deserialize_attestation",
    "verify_request_signature",
    "verify_attestation_signature",
]
