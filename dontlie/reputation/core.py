"""Offline-verifiable public reputation attestations.

An attestation exposes no prompt, response, model, tags, or receipt payload.
Its signed payload has exactly five fields. The envelope adds only the
Ed25519 signature needed to authenticate that payload.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

FORMAT = "dontlie-public-attestation-v1"
REVOCATION_FORMAT = "dontlie-public-revocation-v1"
LINK_PREFIX = "#dl/v1/"
PROMISE_RE = re.compile(r"^v1\.(\d+)\.(\d+)\.([0-9a-f]{32})$")
PAYLOAD_FIELDS = frozenset(
    {
        "receipt_id",
        "chain_tip_hash",
        "public_key",
        "witness_count",
        "truncated_promise",
    }
)


class AttestationError(ValueError):
    """Raised when an attestation cannot be created, parsed, or resolved."""


def _canonical(value: Mapping[str, object]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, altchars=b"-_", validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AttestationError("invalid base64url value") from exc


def _raw_public_key(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def _parse_public_key(value: str) -> Ed25519PublicKey:
    raw = _b64url_decode(value)
    if len(raw) != 32:
        raise AttestationError("public_key must encode a 32-byte Ed25519 key")
    return Ed25519PublicKey.from_public_bytes(raw)


def _validate_hash(value: str, *, name: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{64}", value):
        raise AttestationError(f"{name} must be a lowercase SHA-256 hex digest")


def _commitment_input(
    *,
    receipt_id: int,
    chain_tip_hash: str,
    public_key: str,
    witness_count: int,
    issued_at: int,
    last_corroboration: int,
) -> bytes:
    return _canonical(
        {
            "domain": FORMAT,
            "receipt_id": receipt_id,
            "chain_tip_hash": chain_tip_hash,
            "public_key": public_key,
            "witness_count": witness_count,
            "issued_at": issued_at,
            "last_corroboration": last_corroboration,
        }
    )


def _promise(
    *,
    receipt_id: int,
    chain_tip_hash: str,
    public_key: str,
    witness_count: int,
    issued_at: int,
    last_corroboration: int,
) -> str:
    digest = hashlib.sha256(
        _commitment_input(
            receipt_id=receipt_id,
            chain_tip_hash=chain_tip_hash,
            public_key=public_key,
            witness_count=witness_count,
            issued_at=issued_at,
            last_corroboration=last_corroboration,
        )
    ).hexdigest()[:32]
    return f"v1.{issued_at}.{last_corroboration}.{digest}"


def _promise_times(payload: Mapping[str, object]) -> tuple[int, int]:
    promise = payload.get("truncated_promise")
    if not isinstance(promise, str):
        raise AttestationError("truncated_promise must be a string")
    match = PROMISE_RE.fullmatch(promise)
    if match is None:
        raise AttestationError("invalid truncated_promise")
    issued_at = int(match.group(1))
    last_corroboration = int(match.group(2))
    expected = _promise(
        receipt_id=_int_field(payload, "receipt_id"),
        chain_tip_hash=_str_field(payload, "chain_tip_hash"),
        public_key=_str_field(payload, "public_key"),
        witness_count=_int_field(payload, "witness_count"),
        issued_at=issued_at,
        last_corroboration=last_corroboration,
    )
    if not _constant_time_equal(expected, promise):
        raise AttestationError("truncated_promise commitment does not match payload")
    return issued_at, last_corroboration


def _constant_time_equal(left: str, right: str) -> bool:
    import hmac

    return hmac.compare_digest(left.encode("ascii"), right.encode("ascii"))


def _str_field(value: Mapping[str, object], name: str) -> str:
    item = value.get(name)
    if not isinstance(item, str):
        raise AttestationError(f"{name} must be a string")
    return item


def _int_field(value: Mapping[str, object], name: str) -> int:
    item = value.get(name)
    if isinstance(item, bool) or not isinstance(item, int):
        raise AttestationError(f"{name} must be an integer")
    return item


@dataclass(frozen=True)
class Attestation:
    """Signed five-field public receipt attestation."""

    payload: Mapping[str, object]
    signature: str

    @property
    def address(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    @property
    def link(self) -> str:
        token = base64.b32encode(bytes.fromhex(self.address)).decode("ascii")
        return LINK_PREFIX + token[:20].lower()

    @property
    def signer_fingerprint(self) -> str:
        raw = _b64url_decode(_str_field(self.payload, "public_key"))
        return hashlib.sha256(raw).hexdigest()

    @property
    def issued_at(self) -> datetime:
        issued, _ = _promise_times(self.payload)
        return datetime.fromtimestamp(issued, tz=timezone.utc)

    @property
    def last_corroboration(self) -> datetime | None:
        _, corroborated = _promise_times(self.payload)
        if corroborated == 0:
            return None
        return datetime.fromtimestamp(corroborated, tz=timezone.utc)

    def verify(self, *, now: datetime | None = None) -> None:
        if set(self.payload) != PAYLOAD_FIELDS:
            raise AttestationError("attestation payload must contain exactly five fields")
        receipt_id = _int_field(self.payload, "receipt_id")
        witness_count = _int_field(self.payload, "witness_count")
        if receipt_id < 1:
            raise AttestationError("receipt_id must be positive")
        if witness_count < 0:
            raise AttestationError("witness_count must be non-negative")
        chain_tip_hash = _str_field(self.payload, "chain_tip_hash")
        _validate_hash(chain_tip_hash, name="chain_tip_hash")
        public_key = _parse_public_key(_str_field(self.payload, "public_key"))
        issued_at, corroborated = _promise_times(self.payload)
        current = int((now or datetime.now(timezone.utc)).timestamp())
        if issued_at > current + 300:
            raise AttestationError("attestation issue time is in the future")
        if corroborated > issued_at:
            raise AttestationError("last corroboration is after publication")
        if witness_count == 0 and corroborated != 0:
            raise AttestationError("zero witnesses cannot have a corroboration time")
        if witness_count > 0 and corroborated == 0:
            raise AttestationError("witnessed attestation needs a corroboration time")
        try:
            public_key.verify(_b64url_decode(self.signature), _canonical(self.payload))
        except InvalidSignature as exc:
            raise AttestationError("invalid Ed25519 signature") from exc

    def to_bytes(self) -> bytes:
        return _canonical({"payload": dict(self.payload), "signature": self.signature})

    @classmethod
    def from_bytes(cls, value: bytes) -> Attestation:
        try:
            raw = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AttestationError("attestation is not valid JSON") from exc
        if not isinstance(raw, dict) or set(raw) != {"payload", "signature"}:
            raise AttestationError("invalid attestation envelope")
        payload = raw["payload"]
        signature = raw["signature"]
        if not isinstance(payload, dict) or not isinstance(signature, str):
            raise AttestationError("invalid attestation envelope types")
        attestation = cls(payload=payload, signature=signature)
        attestation.verify()
        return attestation


def build_attestation(
    *,
    receipt_id: int,
    chain_tip_hash: str,
    private_key: Ed25519PrivateKey,
    witness_count: int = 0,
    issued_at: datetime | None = None,
    last_corroboration: datetime | None = None,
) -> Attestation:
    """Create a signed public attestation without exposing receipt content."""
    if receipt_id < 1:
        raise AttestationError("receipt_id must be positive")
    if witness_count < 0:
        raise AttestationError("witness_count must be non-negative")
    _validate_hash(chain_tip_hash, name="chain_tip_hash")
    issued = int((issued_at or datetime.now(timezone.utc)).timestamp())
    corroborated = int(last_corroboration.timestamp()) if last_corroboration else 0
    public_key = _b64url_encode(_raw_public_key(private_key.public_key()))
    payload: dict[str, object] = {
        "receipt_id": receipt_id,
        "chain_tip_hash": chain_tip_hash,
        "public_key": public_key,
        "witness_count": witness_count,
        "truncated_promise": _promise(
            receipt_id=receipt_id,
            chain_tip_hash=chain_tip_hash,
            public_key=public_key,
            witness_count=witness_count,
            issued_at=issued,
            last_corroboration=corroborated,
        ),
    }
    signature = _b64url_encode(private_key.sign(_canonical(payload)))
    attestation = Attestation(payload=payload, signature=signature)
    attestation.verify(now=issued_at)
    return attestation


@dataclass(frozen=True)
class Revocation:
    """Signer-authenticated withdrawal of one public attestation."""

    attestation_address: str
    public_key: str
    revoked_at: int
    signature: str

    @property
    def payload(self) -> dict[str, object]:
        return {
            "format": REVOCATION_FORMAT,
            "attestation_address": self.attestation_address,
            "public_key": self.public_key,
            "revoked_at": self.revoked_at,
        }

    @property
    def address(self) -> str:
        return hashlib.sha256(self.to_bytes()).hexdigest()

    def verify(self, attestation: Attestation) -> None:
        _validate_hash(self.attestation_address, name="attestation_address")
        if self.attestation_address != attestation.address:
            raise AttestationError("revocation addresses a different attestation")
        if self.public_key != attestation.payload["public_key"]:
            raise AttestationError("revocation signer does not match attestation signer")
        public_key = _parse_public_key(self.public_key)
        try:
            public_key.verify(_b64url_decode(self.signature), _canonical(self.payload))
        except InvalidSignature as exc:
            raise AttestationError("invalid revocation signature") from exc

    def to_bytes(self) -> bytes:
        return _canonical({**self.payload, "signature": self.signature})

    @classmethod
    def from_bytes(cls, value: bytes) -> Revocation:
        try:
            raw = json.loads(value)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AttestationError("revocation is not valid JSON") from exc
        expected = {
            "format",
            "attestation_address",
            "public_key",
            "revoked_at",
            "signature",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise AttestationError("invalid revocation envelope")
        if raw["format"] != REVOCATION_FORMAT:
            raise AttestationError("unsupported revocation format")
        return cls(
            attestation_address=str(raw["attestation_address"]),
            public_key=str(raw["public_key"]),
            revoked_at=int(raw["revoked_at"]),
            signature=str(raw["signature"]),
        )


def build_revocation(
    attestation: Attestation,
    private_key: Ed25519PrivateKey,
    *,
    revoked_at: datetime | None = None,
) -> Revocation:
    public_key = _b64url_encode(_raw_public_key(private_key.public_key()))
    if public_key != attestation.payload["public_key"]:
        raise AttestationError("private key does not own this attestation")
    timestamp = int((revoked_at or datetime.now(timezone.utc)).timestamp())
    payload: dict[str, object] = {
        "format": REVOCATION_FORMAT,
        "attestation_address": attestation.address,
        "public_key": public_key,
        "revoked_at": timestamp,
    }
    signature = _b64url_encode(private_key.sign(_canonical(payload)))
    revocation = Revocation(
        attestation_address=attestation.address,
        public_key=public_key,
        revoked_at=timestamp,
        signature=signature,
    )
    revocation.verify(attestation)
    return revocation


class ReputationStore:
    """Filesystem content-addressed store with no network behavior."""

    def __init__(self, root: Path | None = None) -> None:
        configured = os.environ.get("DONTLIE_REPUTATION_DIR")
        self.root = root or Path(
            configured or Path.home() / ".local/share/dontlie/reputation"
        )
        self.attestations = self.root / "attestations"
        self.revocations = self.root / "revocations"

    def put(self, attestation: Attestation) -> Path:
        attestation.verify()
        path = self.attestations / f"{attestation.address}.json"
        self._write_once(path, attestation.to_bytes())
        return path

    def put_revocation(self, revocation: Revocation, attestation: Attestation) -> Path:
        revocation.verify(attestation)
        directory = self.revocations / attestation.address
        path = directory / f"{revocation.address}.json"
        self._write_once(path, revocation.to_bytes())
        return path

    def resolve(self, reference: str) -> Attestation:
        candidate = Path(reference)
        if candidate.is_file():
            return Attestation.from_bytes(candidate.read_bytes())
        token = reference
        if token.startswith(LINK_PREFIX):
            token = token[len(LINK_PREFIX) :]
            if not re.fullmatch(r"[a-z2-7]{20}", token):
                raise AttestationError("invalid attestation link")
            matches = []
            for path in self.attestations.glob("*.json"):
                digest = path.stem
                encoded = base64.b32encode(bytes.fromhex(digest)).decode("ascii")
                if encoded.lower().startswith(token):
                    matches.append(path)
        else:
            if not re.fullmatch(r"[0-9a-f]{12,64}", token):
                raise AttestationError("expected an attestation link, hash, or file")
            matches = list(self.attestations.glob(f"{token}*.json"))
        if len(matches) == 0:
            raise AttestationError("attestation not found in local store")
        if len(matches) > 1:
            raise AttestationError("attestation reference is ambiguous")
        attestation = Attestation.from_bytes(matches[0].read_bytes())
        if matches[0].stem != attestation.address:
            raise AttestationError("stored attestation content hash mismatch")
        return attestation

    def valid_revocations(self, attestation: Attestation) -> tuple[Revocation, ...]:
        directory = self.revocations / attestation.address
        valid: list[Revocation] = []
        for path in directory.glob("*.json"):
            try:
                revocation = Revocation.from_bytes(path.read_bytes())
                revocation.verify(attestation)
                if path.stem != revocation.address:
                    continue
                valid.append(revocation)
            except (AttestationError, OSError, ValueError):
                continue
        return tuple(sorted(valid, key=lambda item: item.revoked_at))

    @staticmethod
    def _write_once(path: Path, value: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        except FileExistsError:
            if path.read_bytes() != value:
                raise AttestationError(f"content-address collision at {path}")
            return
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(value)


@dataclass(frozen=True)
class CheckResult:
    """Human-facing trust state derived entirely offline."""

    attestation: Attestation
    signer_trust: str
    revoked: bool
    age_seconds: int
    revocation: Revocation | None


def check(
    attestation: Attestation,
    *,
    store: ReputationStore,
    trusted_fingerprints: frozenset[str] = frozenset(),
    self_public_key: Ed25519PublicKey | None = None,
    now: datetime | None = None,
) -> CheckResult:
    attestation.verify(now=now)
    fingerprint = attestation.signer_fingerprint
    if self_public_key is not None and _raw_public_key(self_public_key) == _b64url_decode(
        _str_field(attestation.payload, "public_key")
    ):
        trust = "self"
    elif fingerprint in trusted_fingerprints:
        trust = "pinned"
    else:
        trust = "unknown"
    revocations = store.valid_revocations(attestation)
    current = now or datetime.now(timezone.utc)
    age = max(0, int((current - attestation.issued_at).total_seconds()))
    return CheckResult(
        attestation=attestation,
        signer_trust=trust,
        revoked=bool(revocations),
        age_seconds=age,
        revocation=revocations[-1] if revocations else None,
    )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        loaded = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError, TypeError) as exc:
        raise AttestationError(f"cannot load private key: {path}") from exc
    if not isinstance(loaded, Ed25519PrivateKey):
        raise AttestationError("signing key is not Ed25519")
    return loaded


def load_public_fingerprint(value: str) -> str:
    path = Path(value)
    if path.is_file():
        try:
            loaded = serialization.load_pem_public_key(path.read_bytes())
        except (OSError, ValueError, TypeError) as exc:
            raise AttestationError(f"cannot load trusted key: {path}") from exc
        if not isinstance(loaded, Ed25519PublicKey):
            raise AttestationError("trusted key is not Ed25519")
        raw = _raw_public_key(loaded)
    else:
        raw = _b64url_decode(value)
        if len(raw) != 32:
            raise AttestationError("trusted key must encode 32 bytes")
    return hashlib.sha256(raw).hexdigest()
