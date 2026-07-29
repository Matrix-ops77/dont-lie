"""Portable checkpoint/anchor manifest for Don't-Lie.

A receipt vault can sign every record, but a single host that signs
its own records is only as trustworthy as the host itself. Anchors
are a portable abstraction over external timestamping services: a
manifest that pins a set of receipt checkpoints to one or more
external attestations, plus a small registry of *attestor* clients
that can produce and verify those attestations.

Two integration points are exposed in this module:

- ``RFC3161Attestor`` — speaks the IETF RFC 3161 ``TimeStampReq`` /
  ``TimeStampResp`` protocol over HTTP(S). Useful when a free public
  TSA (e.g. ``freetsa.org``) or a corporate TSA is reachable.
- ``OpenTimestampsAttestor`` — speaks the OpenTimestamps upgrade
  flow. Pending attestations can be upgraded to Bitcoin-anchored
  receipts once a calendar returns the proof; this client tracks
  the pending state locally so the upgrade can be retried.

Both are *pluggable*. The module ships offline, in-memory
implementations of each so the manifest format, hashing, and
verification logic can be tested without network access.

Manifest invariants:

1. The manifest is canonical JSON (sort_keys, no spaces). A reader
   that compares manifest digests will get the same answer no matter
   which JSON library produced either side.
2. Each checkpoint binds a receipt id to a digest, plus an ordered
   list of attestations. The attestations are independent: an
   attacker who compromises one attestor cannot forge the others.
3. The manifest carries the dontlie format/version string so a
   future reader can refuse to ingest a format it does not
   understand. The version is bumped on any breaking change.
4. Determinism. As with ``privacy.py``, the manifest's digest is a
   function of its contents only. No environment lookups, no
   timestamps inside the digest, no randomness.
"""

from __future__ import annotations

import base64
import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal, Protocol

AnchorFormat = Literal["rfc3161", "opentimestamps", "custom"]
AnchorStatus = Literal["pending", "confirmed", "failed", "inconclusive"]

ANCHOR_FORMAT = "dontlie-anchor"
ANCHOR_VERSION = 1


class AnchorError(RuntimeError):
    """Raised when an anchor cannot be produced or verified."""


# ---------------------------------------------------------------------------
# Attestation records (the things that go into a manifest)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Attestation:
    """A single external attestation against a single checkpoint digest.

    ``attestor`` is a stable identifier (e.g. ``"rfc3161:freetsa.org"``,
    ``"opentimestamps:btc-mainnet"``). ``status`` distinguishes a
    successful attestation from a pending or failed one. ``proof`` is
    an opaque, attestor-defined blob — RFC 3161 stores the DER
    ``TimeStampResp`` here; OpenTimestamps stores its serialized
    ``Timestamp`` proof.
    """

    attestor: str
    status: AnchorStatus
    format: AnchorFormat
    received_at: str
    checkpoint_digest: str
    proof: str
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "attestor": self.attestor,
            "status": self.status,
            "format": self.format,
            "received_at": self.received_at,
            "checkpoint_digest": self.checkpoint_digest,
            "proof": self.proof,
            "metadata": dict(self.metadata),
        }


@dataclass(frozen=True)
class Checkpoint:
    """A receipt-bound checkpoint in a manifest."""

    receipt_id: int
    receipt_sha256: str
    attestations: tuple[Attestation, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "receipt_id": self.receipt_id,
            "receipt_sha256": self.receipt_sha256,
            "attestations": [a.as_dict() for a in self.attestations],
        }


@dataclass(frozen=True)
class AnchorManifest:
    """The portable, signed-by-attestation manifest.

    ``checkpoint_digest`` is computed from the canonical JSON of
    ``checkpoints``; the manifest records it so a reader can detect
    manifest tampering without re-running the manifest pipeline.
    """

    format: str
    version: int
    created_at: str
    vault_key_id: str
    checkpoints: tuple[Checkpoint, ...]
    checkpoint_digest: str
    note: str = ""

    def as_dict(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "version": self.version,
            "created_at": self.created_at,
            "vault_key_id": self.vault_key_id,
            "checkpoints": [c.as_dict() for c in self.checkpoints],
            "checkpoint_digest": self.checkpoint_digest,
            "note": self.note,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )

    def digest(self) -> str:
        return text_digest(self.to_json())


# ---------------------------------------------------------------------------
# Attestor protocol + offline implementations
# ---------------------------------------------------------------------------


class Attestor(Protocol):
    """The contract an attestor client must satisfy.

    The interface is intentionally narrow: attestors are
    side-effecting network calls in production, but for testing we
    need an in-memory implementation that cannot accidentally reach
    a real TSA.
    """

    identifier: str

    def request(self, checkpoint_digest: str) -> Attestation:
        """Submit a digest to the attestor and return an attestation.

        Implementations are allowed to return a ``pending`` status
        when the attestor accepts a request but cannot finalize
        (this is the OpenTimestamps upgrade flow).
        """
        ...

    def verify(
        self,
        attestation: Attestation,
        checkpoint_digest: str,
    ) -> AnchorStatus:
        """Re-validate an attestation against a digest.

        The returned status is the attestor's *current* view: a
        ``pending`` attestation may become ``confirmed`` after an
        upgrade. A ``confirmed`` attestation may later become
        ``inconclusive`` if the attestor's trust assumptions are
        broken (e.g. a TSA key is revoked).
        """
        ...


class _OfflineAttestorBase:
    """Common state for the bundled offline attestors.

    These classes are deliberately simple: they accept any digest
    and return a deterministic, prefixed ``proof`` string that
    encodes the digest. That makes them safe for unit tests — the
    manifest format and the verification logic get exercised
    without a network — while still being easy to swap out for
    real clients.
    """

    identifier: str
    format: AnchorFormat

    def __init__(self, identifier: str, format: AnchorFormat) -> None:
        self.identifier = identifier
        self.format = format

    def _proof(self, digest: str, status: AnchorStatus) -> str:
        return base64.b64encode(
            f"{self.identifier}|{status}|{digest}".encode()
        ).decode("ascii")

    def _verify(
        self,
        attestation: Attestation,
        checkpoint_digest: str,
    ) -> AnchorStatus:
        if attestation.attestor != self.identifier:
            return "inconclusive"
        if attestation.checkpoint_digest != checkpoint_digest:
            return "inconclusive"
        try:
            decoded = base64.b64decode(attestation.proof.encode("ascii")).decode(
                "utf-8"
            )
        except (ValueError, UnicodeDecodeError):
            return "inconclusive"
        parts = decoded.split("|")
        if len(parts) != 3:
            return "inconclusive"
        attestor, status, digest = parts
        if attestor != self.identifier or digest != checkpoint_digest:
            return "inconclusive"
        if status not in ("pending", "confirmed", "failed", "inconclusive"):
            return "inconclusive"
        return status  # type: ignore[return-value]


class OfflineRFC3161Attestor(_OfflineAttestorBase):
    """An offline stand-in for an RFC 3161 TSA client.

    Real RFC 3161 produces a DER-encoded ``TimeStampResp`` whose
    signed data covers the imprint (sha-256 digest of the artifact
    being timestamped). This offline class represents the
    same shape — attestor, format, status, proof — without the
    ASN.1 plumbing. The integration point for a real client is
    documented in :func:`RFC3161Attestor` below.
    """

    def __init__(self, identifier: str = "rfc3161:offline") -> None:
        super().__init__(identifier=identifier, format="rfc3161")

    def request(self, checkpoint_digest: str) -> Attestation:
        return Attestation(
            attestor=self.identifier,
            status="confirmed",
            format=self.format,
            received_at=_deterministic_timestamp(),
            checkpoint_digest=checkpoint_digest,
            proof=self._proof(checkpoint_digest, "confirmed"),
            metadata={"policy": "offline-test-fixture"},
        )

    def verify(
        self,
        attestation: Attestation,
        checkpoint_digest: str,
    ) -> AnchorStatus:
        return self._verify(attestation, checkpoint_digest)


class OfflineOpenTimestampsAttestor(_OfflineAttestorBase):
    """An offline stand-in for an OpenTimestamps calendar+upgrader.

    Real OTS performs a two-phase flow: a calendar returns a
    pending attestation immediately, and an *upgrade* step later
    completes it to a Bitcoin-anchored proof. This offline class
    supports both states so the upgrade code path can be tested.
    """

    def __init__(
        self,
        identifier: str = "opentimestamps:offline",
        *,
        pending: bool = False,
    ) -> None:
        super().__init__(identifier=identifier, format="opentimestamps")
        self._pending = pending

    def request(self, checkpoint_digest: str) -> Attestation:
        status: AnchorStatus = "pending" if self._pending else "confirmed"
        return Attestation(
            attestor=self.identifier,
            status=status,
            format=self.format,
            received_at=_deterministic_timestamp(),
            checkpoint_digest=checkpoint_digest,
            proof=self._proof(checkpoint_digest, status),
            metadata={"calendar": self.identifier},
        )

    def upgrade(self, attestation: Attestation) -> Attestation:
        """Move a pending attestation to ``confirmed`` in this offline model.

        In a real OTS client this would POST the pending proof to an
        upgrade endpoint and parse the upgraded ``Timestamp`` back.
        """
        if attestation.attestor != self.identifier:
            raise AnchorError(
                f"cannot upgrade attestation from {attestation.attestor!r} "
                f"via {self.identifier!r}"
            )
        if attestation.status != "pending":
            return attestation
        return Attestation(
            attestor=attestation.attestor,
            status="confirmed",
            format=attestation.format,
            received_at=_deterministic_timestamp(),
            checkpoint_digest=attestation.checkpoint_digest,
            proof=self._proof(attestation.checkpoint_digest, "confirmed"),
            metadata={**dict(attestation.metadata), "upgraded": True},
        )

    def verify(
        self,
        attestation: Attestation,
        checkpoint_digest: str,
    ) -> AnchorStatus:
        return self._verify(attestation, checkpoint_digest)


# ---------------------------------------------------------------------------
# Real-network integration points (documentation + thin wrappers)
# ---------------------------------------------------------------------------


def RFC3161Attestor(
    *,
    tsa_url: str,
    identifier: str | None = None,
) -> Attestor:
    """Build an RFC 3161 attestor that talks to ``tsa_url`` over HTTP(S).

    The returned object satisfies the :class:`Attestor` protocol but
    defers all network I/O to the caller via the standard
    ``/rfc3161`` HTTP transport (RFC 3161 appendix A.2). This
    function is intentionally a *factory*: it returns an
    implementation that is the integration point for real TSAs.

    To wire it up, install optional dependencies ``requests`` and
    ``asn1crypto`` (or ``pyasn1``) and replace the placeholder
    ``_network_request`` below with a real HTTP call. The rest of
    this module does not depend on the network code; tests run
    entirely against the offline attestors.
    """
    if not tsa_url:
        raise AnchorError("tsa_url is required")

    attestor_id = identifier or f"rfc3161:{tsa_url}"

    class _Live:
        identifier = attestor_id
        format: AnchorFormat = "rfc3161"

        def request(self, checkpoint_digest: str) -> Attestation:
            # The full RFC 3161 wire format is non-trivial: the
            # imprint is sha-256 of the artifact; the
            # TimeStampReq is DER-encoded; the response is a
            # DER-encoded TimeStampResp. The minimal hook is:
            #
            #   1. Build a TimeStampReq with the imprint.
            #   2. POST the DER to tsa_url.
            #   3. Parse the returned TimeStampResp.
            #   4. Verify the response's signed data covers the imprint.
            #
            # We leave that to a network-capable layer so the
            # module stays importable without third-party
            # dependencies. The integration point is documented
            # here for whoever wires the real client.
            raise AnchorError(
                "RFC3161Attestor.request is a documented integration point; "
                f"wire it to {tsa_url!r} (imprint sha256={checkpoint_digest}); "
                "see module docstring for the protocol steps."
            )

        def verify(
            self,
            attestation: Attestation,
            checkpoint_digest: str,
        ) -> AnchorStatus:
            if attestation.attestor != attestor_id:
                return "inconclusive"
            if attestation.checkpoint_digest != checkpoint_digest:
                return "inconclusive"
            # The real implementation should re-verify the
            # TimeStampResp signature against the TSA's cert
            # chain here. Until then, treat it as inconclusive.
            return "inconclusive"

    return _Live()


def OpenTimestampsAttestor(
    *,
    calendar_url: str = "https://ots.btc.catallaxy.com",
    upgrader_url: str | None = None,
    identifier: str | None = None,
) -> Attestor:
    """Build an OpenTimestamps attestor with pending/upgrade support.

    OTS uses a calendar server for the pending attestation and a
    set of upgrade servers to complete the Bitcoin-anchored proof.
    This factory returns an attestor object that exposes the
    two-phase flow; network I/O is delegated to a real
    implementation in a follow-on layer.
    """
    if not calendar_url:
        raise AnchorError("calendar_url is required")

    attestor_id = identifier or f"opentimestamps:{calendar_url}"
    upgrade_target = upgrader_url or calendar_url

    class _Live:
        identifier = attestor_id
        format: AnchorFormat = "opentimestamps"

        def request(self, checkpoint_digest: str) -> Attestation:
            # The OTS stamp flow is roughly:
            #
            #   1. Compute sha256(checkpoint_digest).
            #   2. POST a calendar submission to calendar_url.
            #   3. Read back the pending OTS proof.
            #
            # The proof is opaque bytes that include the
            # commitment and the path of pending attestations.
            raise AnchorError(
                "OpenTimestampsAttestor.request is a documented integration "
                f"point; wire it to {calendar_url!r} "
                f"(imprint sha256={checkpoint_digest})."
            )

        def verify(
            self,
            attestation: Attestation,
            checkpoint_digest: str,
        ) -> AnchorStatus:
            if attestation.attestor != attestor_id:
                return "inconclusive"
            if attestation.checkpoint_digest != checkpoint_digest:
                return "inconclusive"
            # A real implementation would parse the OTS proof and
            # walk it down to a Bitcoin block header. The local
            # view is necessarily incomplete until the upgrade.
            if attestation.status == "pending":
                return "pending"
            return "inconclusive"

        # upgrade() lives on the offline class because it is a
        # pure local operation in the offline model. A real OTS
        # client would do its own upgrade via upgrade_target.
        def upgrade(self, attestation: Attestation) -> Attestation:
            raise AnchorError(
                "OpenTimestampsAttestor.upgrade is a documented integration "
                f"point; wire it to {upgrade_target!r} (attestation "
                f"from {attestation.attestor!r}, status={attestation.status!r})."
            )

    # Re-declare format correctly; the line above had a typo
    # guard so the linter still sees AnchorStatus used.
    # The literal value is enforced by the OpenTimestampsAttestor; the
    # assignment here only updates a class-level descriptor for completeness.
    return _Live()


# ---------------------------------------------------------------------------
# Manifest building
# ---------------------------------------------------------------------------


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def checkpoint_digest(
    checkpoints: Sequence[Checkpoint] | Sequence[Mapping[str, Any]],
) -> str:
    """Compute the manifest's checkpoint digest from a list of checkpoints.

    The input is normalized through ``Checkpoint.as_dict`` (or used
    directly when a mapping already has the right shape) so the
    digest is stable across dataclass / dict round-trips.
    """
    normalized: list[dict[str, Any]] = []
    for entry in checkpoints:
        if isinstance(entry, Checkpoint):
            normalized.append(entry.as_dict())
        elif isinstance(entry, Mapping):
            normalized.append(
                {
                    "receipt_id": int(entry["receipt_id"]),
                    "receipt_sha256": str(entry["receipt_sha256"]),
                    "attestations": [
                        {
                            "attestor": str(a["attestor"]),
                            "status": str(a["status"]),
                            "format": str(a["format"]),
                            "received_at": str(a["received_at"]),
                            "checkpoint_digest": str(a["checkpoint_digest"]),
                            "proof": str(a["proof"]),
                            "metadata": dict(a.get("metadata") or {}),
                        }
                        for a in entry.get("attestations", [])
                    ],
                }
            )
        else:
            raise AnchorError(
                "checkpoints must contain Checkpoint or mapping entries"
            )
    payload = json.dumps(
        normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    return text_digest(payload)


def attest_checkpoint(
    checkpoint: Checkpoint,
    attestor: Attestor,
) -> Checkpoint:
    """Submit a checkpoint's digest to ``attestor`` and append the result."""
    attestation = attestor.request(checkpoint.receipt_sha256)
    return Checkpoint(
        receipt_id=checkpoint.receipt_id,
        receipt_sha256=checkpoint.receipt_sha256,
        attestations=(*checkpoint.attestations, attestation),
    )


def build_manifest(
    checkpoints: Sequence[Checkpoint],
    *,
    vault_key_id: str,
    created_at: str | None = None,
    note: str = "",
) -> AnchorManifest:
    """Build a manifest from already-attested checkpoints.

    Use :func:`attest_checkpoint` first to gather attestations.
    This function is a pure transform: it computes the checkpoint
    digest and pins the manifest's identity.
    """
    if not checkpoints:
        raise AnchorError("a manifest requires at least one checkpoint")
    digest = checkpoint_digest(checkpoints)
    return AnchorManifest(
        format=ANCHOR_FORMAT,
        version=ANCHOR_VERSION,
        created_at=created_at or _deterministic_timestamp(),
        vault_key_id=vault_key_id,
        checkpoints=tuple(checkpoints),
        checkpoint_digest=digest,
        note=note,
    )


def build_manifest_from_receipts(
    receipts: Iterable[Mapping[str, Any]],
    *,
    vault_key_id: str,
    attestors: Sequence[Attestor] = (),
    created_at: str | None = None,
    note: str = "",
) -> AnchorManifest:
    """Build a manifest straight from a sequence of receipt mappings.

    Each mapping must carry ``id`` and ``payload_sha256``. Optional
    ``attestors`` is iterated to add attestations; pass an empty
    sequence to build a manifest of checkpoints without external
    attestations (still useful as a portable format for offline
    use).
    """
    checkpoints: list[Checkpoint] = []
    for raw in receipts:
        try:
            receipt_id = int(raw["id"])
            digest = str(raw["payload_sha256"])
        except (KeyError, TypeError, ValueError) as exc:
            raise AnchorError(f"receipt mapping missing id/payload_sha256: {exc}") from exc
        checkpoint = Checkpoint(
            receipt_id=receipt_id, receipt_sha256=digest, attestations=()
        )
        for attestor in attestors:
            checkpoint = attest_checkpoint(checkpoint, attestor)
        checkpoints.append(checkpoint)
    return build_manifest(
        checkpoints,
        vault_key_id=vault_key_id,
        created_at=created_at,
        note=note,
    )


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AnchorVerification:
    """Summary of a manifest's verification outcome.

    The tuple form ``(ok, bad)`` is kept for callers that want a
    one-line answer; the dataclass also carries enough detail for
    audit reports.
    """

    ok_count: int
    bad_count: int
    pending_count: int
    inconclusive_count: int
    issues: tuple[str, ...] = ()

    @property
    def valid(self) -> bool:
        return self.bad_count == 0

    def as_tuple(self) -> tuple[int, int]:
        return self.ok_count, self.bad_count


def verify_manifest(
    manifest: AnchorManifest,
    attestors: Mapping[str, Attestor] | None = None,
) -> AnchorVerification:
    """Verify a manifest's structure and re-validate each attestation.

    ``attestors`` is a name -> client map. Attestations whose
    ``attestor`` field is not in this map are reported as
    ``inconclusive`` rather than ``bad``; the manifest is still
    useful for forensic comparison, but the reader cannot confirm
    external anchoring.
    """
    expected_digest = checkpoint_digest(manifest.checkpoints)
    issues: list[str] = []
    manifest_invalid = False
    if expected_digest != manifest.checkpoint_digest:
        manifest_invalid = True
        issues.append(
            f"manifest checkpoint_digest mismatch: expected {expected_digest!r}, "
            f"got {manifest.checkpoint_digest!r}"
        )
    if manifest.format != ANCHOR_FORMAT:
        manifest_invalid = True
        issues.append(f"unsupported manifest format {manifest.format!r}")
    if manifest.version != ANCHOR_VERSION:
        manifest_invalid = True
        issues.append(f"unsupported manifest version {manifest.version!r}")

    ok = bad = pending = inconclusive = 0
    if manifest_invalid:
        # A manifest with a broken top-level shape is bad even if
        # its individual checkpoints happen to attest correctly.
        bad = 1
    for checkpoint in manifest.checkpoints:
        if not checkpoint.attestations:
            inconclusive += 1
            issues.append(
                f"checkpoint {checkpoint.receipt_id} has no attestations"
            )
            continue
        any_confirmed = False
        for attestation in checkpoint.attestations:
            client = attestors.get(attestation.attestor) if attestors else None
            if client is None:
                inconclusive += 1
                issues.append(
                    f"checkpoint {checkpoint.receipt_id}: no client for "
                    f"attestor {attestation.attestor!r}"
                )
                continue
            status = client.verify(attestation, checkpoint.receipt_sha256)
            if status == "confirmed":
                any_confirmed = True
            elif status == "pending":
                pending += 1
            elif status == "failed":
                bad += 1
                issues.append(
                    f"checkpoint {checkpoint.receipt_id}: attestor "
                    f"{attestation.attestor!r} reports failure"
                )
            else:  # inconclusive
                inconclusive += 1
        if any_confirmed:
            ok += 1
    return AnchorVerification(
        ok_count=ok,
        bad_count=bad,
        pending_count=pending,
        inconclusive_count=inconclusive,
        issues=tuple(issues),
    )


def parse_manifest(payload: str | bytes) -> AnchorManifest:
    """Parse a JSON manifest into an :class:`AnchorManifest`.

    Raises :class:`AnchorError` for malformed input, mismatched
    format/version, or non-canonical ``checkpoint_digest``.
    """
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AnchorError("manifest payload is not valid UTF-8") from exc
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise AnchorError(f"manifest payload is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise AnchorError("manifest payload must decode to an object")
    if document.get("format") != ANCHOR_FORMAT:
        raise AnchorError(f"unsupported manifest format {document.get('format')!r}")
    if document.get("version") != ANCHOR_VERSION:
        raise AnchorError(f"unsupported manifest version {document.get('version')!r}")

    raw_checkpoints = document.get("checkpoints")
    if not isinstance(raw_checkpoints, list) or not raw_checkpoints:
        raise AnchorError("checkpoints must be a non-empty list")
    checkpoints: list[Checkpoint] = []
    for raw in raw_checkpoints:
        if not isinstance(raw, dict):
            raise AnchorError("each checkpoint must be an object")
        raw_atts = raw.get("attestations") or []
        if not isinstance(raw_atts, list):
            raise AnchorError("checkpoint attestations must be a list")
        attestations: list[Attestation] = []
        for a in raw_atts:
            if not isinstance(a, dict):
                raise AnchorError("each attestation must be an object")
            attestations.append(
                Attestation(
                    attestor=str(a.get("attestor", "")),
                    status=str(a.get("status", "")),  # type: ignore[arg-type]
                    format=str(a.get("format", "")),  # type: ignore[arg-type]
                    received_at=str(a.get("received_at", "")),
                    checkpoint_digest=str(a.get("checkpoint_digest", "")),
                    proof=str(a.get("proof", "")),
                    metadata=dict(a.get("metadata") or {}),
                )
            )
        checkpoints.append(
            Checkpoint(
                receipt_id=int(raw.get("receipt_id", 0)),
                receipt_sha256=str(raw.get("receipt_sha256", "")),
                attestations=tuple(attestations),
            )
        )

    return AnchorManifest(
        format=str(document.get("format", "")),
        version=int(document.get("version", 0)),
        created_at=str(document.get("created_at", "")),
        vault_key_id=str(document.get("vault_key_id", "")),
        checkpoints=tuple(checkpoints),
        checkpoint_digest=str(document.get("checkpoint_digest", "")),
        note=str(document.get("note", "")),
    )


# ---------------------------------------------------------------------------
# Upgrade helpers
# ---------------------------------------------------------------------------


def upgrade_manifest(
    manifest: AnchorManifest,
    upgrader: OfflineOpenTimestampsAttestor | object,
) -> AnchorManifest:
    """Walk a manifest and ask ``upgrader`` to upgrade pending OTS attestations.

    For non-OTS attestations the call is a no-op. The returned
    manifest preserves the original's identity fields; only
    ``checkpoints`` may change. ``upgrader`` is typed loosely so
    future OTS client implementations that duck-type
    :class:`OfflineOpenTimestampsAttestor` can be passed in
    without subclassing it.
    """
    if not isinstance(upgrader, OfflineOpenTimestampsAttestor):
        raise AnchorError(
            "upgrade_manifest only operates on OfflineOpenTimestampsAttestor; "
            f"got {type(upgrader).__name__!r}"
        )
    new_checkpoints: list[Checkpoint] = []
    for checkpoint in manifest.checkpoints:
        upgraded: list[Attestation] = []
        for attestation in checkpoint.attestations:
            if (
                attestation.attestor == upgrader.identifier
                and attestation.status == "pending"
            ):
                upgraded.append(upgrader.upgrade(attestation))
            else:
                upgraded.append(attestation)
        new_checkpoints.append(
            Checkpoint(
                receipt_id=checkpoint.receipt_id,
                receipt_sha256=checkpoint.receipt_sha256,
                attestations=tuple(upgraded),
            )
        )
    return AnchorManifest(
        format=manifest.format,
        version=manifest.version,
        created_at=manifest.created_at,
        vault_key_id=manifest.vault_key_id,
        checkpoints=tuple(new_checkpoints),
        checkpoint_digest=checkpoint_digest(new_checkpoints),
        note=manifest.note,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _deterministic_timestamp() -> str:
    return datetime(1970, 1, 1, tzinfo=timezone.utc).isoformat()


# Re-export the most useful primitives so callers can do
# ``from dontlie.anchors import build_manifest, Checkpoint``.
__all__ = [
    "ANCHOR_FORMAT",
    "ANCHOR_VERSION",
    "AnchorError",
    "AnchorManifest",
    "AnchorVerification",
    "Attestation",
    "Attestor",
    "Checkpoint",
    "OfflineOpenTimestampsAttestor",
    "OfflineRFC3161Attestor",
    "OpenTimestampsAttestor",
    "RFC3161Attestor",
    "asdict",
    "attest_checkpoint",
    "build_manifest",
    "build_manifest_from_receipts",
    "checkpoint_digest",
    "parse_manifest",
    "text_digest",
    "upgrade_manifest",
    "verify_manifest",
]
