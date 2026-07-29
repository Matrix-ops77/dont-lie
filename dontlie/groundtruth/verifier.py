"""Witness verification: cross-checks an attestation against a key db.

A verifier receives a `PeerWitnessAttestation` and either trusts the
named `witness_key_id` (and looks up its public key in a key db) or
rejects the attestation. The default `WitnessVerification` returns a
structured `(ok, reason)` pair rather than raising, so the higher-level
`verify_route_attestation` can fold witness results into its overall
verdict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .client import WitnessKey
from .envelope import (
    PeerWitnessAttestation,
    PeerWitnessRequest,
    verify_attestation_signature,
    verify_request_signature,
)


@dataclass(frozen=True)
class WitnessVerification:
    """Result of verifying a single witness attestation."""

    ok: bool
    reason: str = ""
    witness_key_id: str = ""

    def __bool__(self) -> bool:  # truthy iff verification passed
        return self.ok


class WitnessVerifier:
    """Verifies attestations against a known map of witness keys.

    The key db is supplied by the operator; the verifier does not
    discover keys on its own. This keeps the trust boundary explicit
    and lets an operator pin a small set of witness keys rather than
    trusting whatever happens to be reachable.
    """

    def __init__(self, witness_keys: Mapping[str, WitnessKey]) -> None:
        if not witness_keys:
            raise ValueError("witness_keys must be a non-empty mapping")
        self._keys = dict(witness_keys)

    @property
    def key_ids(self) -> set[str]:
        return set(self._keys.keys())

    def verify(self, attestation: PeerWitnessAttestation) -> WitnessVerification:
        kid = attestation.witness_key_id
        if kid not in self._keys:
            return WitnessVerification(
                ok=False, reason=f"unknown witness key id: {kid!r}", witness_key_id=kid
            )
        # Reject expired requests regardless of signature.
        if attestation.request.is_expired():
            return WitnessVerification(
                ok=False, reason="request expired", witness_key_id=kid
            )
        if not verify_attestation_signature(attestation, self._keys[kid].public_key):
            return WitnessVerification(
                ok=False, reason="witness signature failed", witness_key_id=kid
            )
        return WitnessVerification(ok=True, witness_key_id=kid)

    def verify_request(self, request: PeerWitnessRequest, requester_public_key: Ed25519PublicKey) -> bool:
        """The witness side of the protocol: verify the requester signed the request."""
        if request.is_expired():
            return False
        return verify_request_signature(request, requester_public_key)


__all__ = ["WitnessVerification", "WitnessVerifier"]
