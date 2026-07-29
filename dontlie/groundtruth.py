"""Don't-Lie ground-truth lane (proof-of-route).

This module is a thin façade over :mod:`dontlie.groundtruth` (the
subpackage). It re-exports the public API for callers that import
``dontlie.groundtruth`` as a module and keeps the BlindProbe /
RouteAttestation helpers that the rest of the codebase depends on.

Design notes (full threat model and privacy story in
``docs/groundtruth.md``):

* The lane is opt-in. The default ``BlindProbe(mode="offline")`` and
  ``OfflineWitness`` both short-circuit before any network call.
* Witnesses only ever see SHA-256 digests and a short random nonce;
  prompts and responses never cross the witness boundary.
* Every signature covers the canonical JSON of the payload with the
  signature field itself excluded.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .groundtruth import (
    InProcessWitness,
    OfflineWitness,
    PeerWitnessAttestation,
    PeerWitnessRequest,
    RemoteHTTPWitness,
    Witness,
    WitnessError,
    WitnessKey,
    WitnessVerification,
    WitnessVerifier,
    build_signed_request,
    deserialize_attestation,
    deserialize_request,
    digest_payload,
    serialize_attestation,
    serialize_request,
    short_nonce,
    verify_attestation_signature,
    verify_request_signature,
)


# --- exceptions --------------------------------------------------------------


class BlindProbeUnavailable(RuntimeError):
    """Raised when no runner is attached and no network fallback is wired."""


class RouteMismatchError(Exception):
    """Raised when a route attestation does not match the receipt/probe."""


# --- blind probe -------------------------------------------------------------


@dataclass
class BlindProbeResult:
    provider: str
    model: str
    response_sha256: str
    response_digest: str
    elapsed_ms: int
    correlation_id: str

    def canonical(self) -> dict[str, Any]:
        return asdict(self)


_RUNNER: Optional[Any] = None


def attach_runner(runner: Any) -> None:
    """Inject a runner that the blind probe will dispatch to.

    The runner may be either a callable ``prompt -> BlindProbeResult`` or an
    object exposing a ``run(prompt)`` method (duck-typed). Both shapes are
    supported so callers can subclass or compose without ceremony.
    """
    global _RUNNER
    _RUNNER = runner


def reset_runner() -> None:
    """Drop any attached runner."""
    global _RUNNER
    _RUNNER = None


class BlindProbe:
    """Send a blinded probe to the configured upstream provider.

    The default mode is ``offline`` and rejects any ``run`` call; callers
    must ``attach_runner`` (or supply a custom factory) to make the
    probe actually contact an upstream.
    """

    MODES = ("offline", "runner")

    def __init__(self, mode: str = "offline") -> None:
        if mode not in self.MODES:
            raise ValueError(f"unsupported mode: {mode!r}")
        self.mode = mode

    def run(self, prompt: str) -> BlindProbeResult:
        if _RUNNER is None:
            raise BlindProbeUnavailable(
                "no runner attached; call attach_runner() first"
            )
        if callable(_RUNNER):
            return _RUNNER(prompt)
        run = getattr(_RUNNER, "run", None)
        if run is None:
            raise BlindProbeUnavailable(
                "attached runner exposes neither __call__ nor .run"
            )
        return run(prompt)


# --- route attestation ------------------------------------------------------


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


def _sign_payload(payload: bytes, private_key: Ed25519PrivateKey) -> str:
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
    import json

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
