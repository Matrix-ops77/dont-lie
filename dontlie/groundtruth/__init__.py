"""Don't-Lie ground-truth lane: peer-witness subpackage.

The subpackage is split into:

* :mod:`.probe`    — ``BlindProbe`` and ``BlindProbeResult`` (the
  operator-side blinded-call API; offline by default)
* :mod:`.attestation` — ``RouteAttestation`` + ``attest_receipt`` /
  ``verify_route_attestation`` (link a receipt to a probe result)
* :mod:`.envelope` — ``PeerWitnessRequest`` / ``PeerWitnessAttestation``
  wire format and sign / verify helpers
* :mod:`.client`   — ``Witness`` transports: ``OfflineWitness`` (default),
  ``InProcessWitness``, ``RemoteHTTPWitness`` (stub)
* :mod:`.verifier` — ``WitnessVerifier`` + ``WitnessVerification`` result
* :mod:`.helpers`  — ``short_nonce`` and ``digest_payload`` shared by all

The top-level :mod:`dontlie.groundtruth` module is a thin façade that
re-exports the public API for callers that prefer the flat-module
form (``import dontlie.groundtruth as gt``).
"""

from __future__ import annotations

from .attestation import (
    RouteAttestation,
    RouteMismatchError,
    attest_receipt,
    verify_route_attestation,
)
from .client import (
    InProcessWitness,
    OfflineWitness,
    RemoteHTTPWitness,
    Witness,
    WitnessError,
    WitnessKey,
)
from .envelope import (
    PeerWitnessAttestation,
    PeerWitnessRequest,
    build_signed_request,
    deserialize_attestation,
    deserialize_request,
    serialize_attestation,
    serialize_request,
    verify_attestation_signature,
    verify_request_signature,
)
from .helpers import digest_payload, short_nonce
from .probe import BlindProbe, BlindProbeResult, BlindProbeUnavailable, attach_runner, reset_runner
from .verifier import WitnessVerification, WitnessVerifier

__all__ = [
    "BlindProbe",
    "BlindProbeResult",
    "BlindProbeUnavailable",
    "InProcessWitness",
    "OfflineWitness",
    "PeerWitnessAttestation",
    "PeerWitnessRequest",
    "RemoteHTTPWitness",
    "RouteAttestation",
    "RouteMismatchError",
    "Witness",
    "WitnessError",
    "WitnessKey",
    "WitnessVerification",
    "WitnessVerifier",
    "attach_runner",
    "attest_receipt",
    "build_signed_request",
    "deserialize_attestation",
    "deserialize_request",
    "digest_payload",
    "reset_runner",
    "serialize_attestation",
    "serialize_request",
    "short_nonce",
    "verify_attestation_signature",
    "verify_request_signature",
    "verify_route_attestation",
]
