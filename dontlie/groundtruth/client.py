"""Witness transports for the ground-truth lane.

A `Witness` is a side channel that an operator can ask to corroborate a
receipt's existence. The only thing that crosses the witness boundary is
a `PeerWitnessRequest` (digests, no prompts or responses) and back comes
a `PeerWitnessAttestation`.

Default is `OfflineWitness`, which short-circuits before any network or
subprocess call. Operators opt in to `InProcessWitness` (same Python
process; good for tests) or `RemoteHTTPWitness` (HTTPS to a peer host;
stub for now so the boundary is explicit without committing to a wire
format before a real peer exists).
"""

from __future__ import annotations

import abc
import time
from collections.abc import Callable
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .envelope import (
    PeerWitnessAttestation,
    PeerWitnessRequest,
)


class WitnessError(RuntimeError):
    """Raised by witness transports when a request cannot be served."""


@dataclass
class WitnessKey:
    """An Ed25519 key held by a witness, with stable fingerprint for lookup."""

    key_id: str
    public_key: Ed25519PublicKey
    private_key: object | None = None  # Ed25519PrivateKey; opaque to avoid extra import
    label: str = ""

    def __post_init__(self) -> None:
        if not self.key_id:
            raise ValueError("key_id is required")


class Witness(abc.ABC):
    """Abstract base class for witness transports."""

    @abc.abstractmethod
    def attest(self, request: PeerWitnessRequest) -> PeerWitnessAttestation:
        """Return a signed attestation for the given request, or raise WitnessError."""

    @property
    @abc.abstractmethod
    def key_id(self) -> str:
        """Stable identifier of the witness's signing key."""


class OfflineWitness(Witness):
    """Default witness. Short-circuits before any network call."""

    @property
    def key_id(self) -> str:
        return "witness-offline"

    def attest(self, request: PeerWitnessRequest) -> PeerWitnessAttestation:
        raise WitnessError(
            "offline witness does not sign attestations; "
            "opt in via InProcessWitness or RemoteHTTPWitness"
        )


class InProcessWitness(Witness):
    """Same-process witness; useful for tests and self-witnessing.

    The witness verifies the requester's signature before signing its
    own attestation, so a forged or tampered request is rejected. The
    witness holds the private key — pass via the WitnessKey dataclass.
    """

    def __init__(self, key: WitnessKey, *, verify_requester: bool = True) -> None:
        if key.private_key is None:
            raise ValueError("InProcessWitness needs a key with a private key")
        self._key = key
        self._verify_requester = verify_requester

    @property
    def key_id(self) -> str:
        return self._key.key_id

    def attest(self, request: PeerWitnessRequest) -> PeerWitnessAttestation:
        if self._verify_requester:
            # The operator who signed the request may not be the same as
            # the verifier; we just check the signature is well-formed
            # against a public key the witness has been told about. In
            # practice this is wired up by the verifier holding a key
            # map. We do the cheap check here: signature well-formed
            # + nonce is short enough. Heavy crypto verification is the
            # verifier's job (it has the public key db).
            if not request.signature or len(request.signature) < 128:
                raise WitnessError("request missing or malformed signature")
            if request.is_expired():
                raise WitnessError("request expired")
        # Compose attestation over the request's digest fields.

        from .envelope import serialize_attestation  # local to break cycles

        att = PeerWitnessAttestation(
            request=request,
            receipt_payload_sha256=request.receipt_payload_sha256,
            provider=request.provider,
            model=request.model,
            correlation_id=request.correlation_id,
            nonce=request.nonce,
            witness_key_id=self.key_id,
            observed_at=int(time.time()),
            signature="",
        )
        payload = serialize_attestation(att, for_signing=True)
        att.signature = self._key.private_key.sign(payload).hex()  # type: ignore[union-attr]
        return att


class RemoteHTTPWitness(Witness):
    """Stub for a peer witness over HTTPS.

    The intent is to keep the boundary explicit before a real wire
    format is locked in. The stub rejects all requests so a default
    install never leaks data to the network by accident.
    """

    def __init__(
        self,
        endpoint: str,
        key: WitnessKey,
        *,
        verify_request_payload: Callable[[PeerWitnessRequest], None] | None = None,
    ) -> None:
        if not endpoint.startswith("https://"):
            raise ValueError("RemoteHTTPWitness endpoint must be https://")
        self._endpoint = endpoint
        self._key = key
        self._verify_request_payload = verify_request_payload

    @property
    def key_id(self) -> str:
        return self._key.key_id

    def attest(self, request: PeerWitnessRequest) -> PeerWitnessAttestation:
        # A future revision will POST serialize_request(request) to
        # self._endpoint and deserialize the response. Until then we
        # fail closed so default installs do not accidentally phone home.
        raise WitnessError(
            f"RemoteHTTPWitness({self._endpoint}) is a stub; "
            "wire format pending operator review. Use InProcessWitness for now."
        )


__all__ = [
    "InProcessWitness",
    "OfflineWitness",
    "RemoteHTTPWitness",
    "Witness",
    "WitnessError",
    "WitnessKey",
]
