"""SCITT-compatible signed-statement envelopes for Don't-Lie receipts.

**Design note (TL;DR).** IETF SCITT (RFC 9943, June 2026) defines a
"Transparency Service" that ingests Signed Statements about artifacts and
emits Receipts proving their inclusion. The most natural mapping is: each
Don't-Lie receipt is a Signed Statement, the local SQLite chain is a
one-writer registry, and the existing ``witness-worker`` co-signing is a
litewitness over it. This module emits per-receipt Signed Statements as
``COSE_Sign1`` envelopes (RFC 9052) so any standard SCITT verifier can
read them.

**Envelope layout.** A COSE_Sign1 structure is the 4-element CBOR array::

    [protected, unprotected, payload, signature]

where ``protected`` is a CBOR-encoded map (the *protected header*),
``unprotected`` is a CBOR map (the *unprotected header*), ``payload`` is
a CBOR byte string, and ``signature`` is a CBOR byte string. The
signature is computed over the ``Sig_structure``::

    ["Signature1", protected_bstr, external_aad_bstr, payload_bstr]

The protected header carries the algorithm (``alg = -8`` for Ed25519,
per the IANA COSE Algorithms registry) and the content type
(``application/dontlie-receipt-sha256``). The unprotected header carries
Don't-Lie-specific labels starting at 99999 to avoid collision with the
IANA COSE Header Parameters registry: 99999 = ``kid`` (the receipt's
``key_id``), 99998 = ``operator_key_id``, 99997 = ``chain_version``,
99996 = ``receipt_id``, 99995 = ``payload_sha256`` (the hex form, for
humans), 99994 = ``parent_id``, 99993 = ``model``, 99992 = ``timestamp``.

**Payload choice.** The brief asks for the receipt's ``payload_sha256``
to be the COSE payload, *not* the full receipt body. This keeps
envelopes small (~150 bytes each) and means a SCITT verifier can prove
"this 32-byte hash was signed by key K at time T" without seeing the
prompt or response. A receiver who wants the full body uses the
``payload_sha256`` from the unprotected header to look up the receipt
in the don't-lie vault (or a bundle export).

**Trade-offs vs RFC 9052 byte-perfect conformance.** We emit a JSON-
wrappable form (``{"protected": b64u, "unprotected": {...}, "payload":
b64u, "signature": b64u}``) with base64url-encoded bstr fields. SCITT
receivers that ingest JSON envelopes (the pycose ``Sign1.from_json``
path, the SCITT Reference API "SCRAPI" HTTP transport) accept this
form. The "pure" CBOR form (a 4-element array) is also produced by
:func:`emit_envelope_cbor` for receivers that want it; both forms
round-trip through the same Ed25519 verification path. We do not
emit the SCITT "tag 18" tag wrapper — receivers that require it can
add the tag in one line. We do not include a Merkle inclusion proof
in the envelope itself; that is the role of a separate SCITT Receipt
(see ``draft-ietf-cose-merkle-tree-proofs``), which is produced by
``dontlie anchor daily`` and not in scope here.
"""
from __future__ import annotations

import base64
import json
import struct
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import sign as signing
from . import storage

# ---- COSE / SCITT constants ------------------------------------------------

# COSE algorithm identifier for Ed25519 (RFC 9052 §7.1, IANA COSE Algorithms).
COSE_ALG_ED25519 = -8

# COSE common header label "content type" (RFC 9052 §3.1). The "3" label
# in IANA COSE Header Parameters.
COSE_LABEL_CONTENT_TYPE = 3
# COSE common header label "alg" (RFC 9052 §3.1). The "1" label.
COSE_LABEL_ALG = 1

# Our content type for the receipt's payload. The payload is the raw
# 32-byte SHA-256 of the receipt's canonical encoding, not the body.
CONTENT_TYPE_RECEIPT_HASH = "application/dontlie-receipt-sha256"

# Don't-Lie-specific header labels. We start at 99999 to stay clear of
# the IANA COSE Header Parameters registry (currently allocated through
# ~50-something). These labels are unprotected — they ride alongside
# the signature, not inside the signed bytes.
LABEL_KID = 99999               # the receipt's signing key_id
LABEL_OPERATOR_KEY_ID = 99998   # v3: operator identity (Article 12(3))
LABEL_CHAIN_VERSION = 99997     # v2 or v3
LABEL_RECEIPT_ID = 99996        # monotonic id
LABEL_PAYLOAD_SHA256 = 99995    # hex of the COSE payload (echo for humans)
LABEL_PARENT_ID = 99994         # chain parent (-1 = none)
LABEL_MODEL = 99993             # model name (free string)
LABEL_TIMESTAMP = 99992         # ISO 8601 UTC

# Sig_structure context string for COSE_Sign1 (RFC 9052 §4.4).
SIGNATURE_CONTEXT = b"Signature1"

# External AAD is empty in v1 (we don't use it).
EXTERNAL_AAD = b""

# Don't-Lie chain version we use when ``extra`` doesn't carry one (legacy v2).
LEGACY_CHAIN_VERSION = 2


# ---- minimal CBOR encoder/decoder (stdlib only) ----------------------------
#
# We implement just enough CBOR to round-trip the COSE_Sign1 structure we
# produce and the few test fields we need to inspect. Major types follow
# RFC 8949 §3.1. Integers use the "negative" form for n >= -24; larger
# negative values are encoded as the unsigned form of ``(1 + |n|)`` then
# tagged negative. We do not implement tags (we use the untagged form),
# floats, bignums, or indefinite-length items. That covers everything
# RFC 9052 requires for COSE_Sign1 with integer/text/byte/map/array
# structures.
#
# Deviations from RFC 8949: none of consequence. The decoder is strict
# enough to reject malformed input. The encoder produces canonical
# (length-sorted) maps, which is required for the protected header to
# be reproducible across runs.


def _cbor_encode_uint(value: int) -> bytes:
    if value < 0:
        raise ValueError("use _cbor_encode_int for negatives")
    if value <= 23:
        return bytes([value])
    if value <= 0xFF:
        return bytes([0x18, value])
    if value <= 0xFFFF:
        return bytes([0x19]) + struct.pack(">H", value)
    if value <= 0xFFFFFFFF:
        return bytes([0x1A]) + struct.pack(">I", value)
    if value <= 0xFFFFFFFFFFFFFFFF:
        return bytes([0x1B]) + struct.pack(">Q", value)
    raise ValueError(f"uint too large: {value}")


def _cbor_encode_int(value: int) -> bytes:
    """CBOR major type 0/1 for any signed int."""
    if value >= 0:
        return _cbor_encode_uint(value)
    n = -1 - value  # value=-1 -> n=0; value=-24 -> n=23; value=-25 -> n=24
    if n <= 23:
        return bytes([0x20 | n])
    if n <= 0xFF:
        return bytes([0x38, n])
    if n <= 0xFFFF:
        return bytes([0x39]) + struct.pack(">H", n)
    if n <= 0xFFFFFFFF:
        return bytes([0x3A]) + struct.pack(">I", n)
    if n <= 0xFFFFFFFFFFFFFFFF:
        return bytes([0x3B]) + struct.pack(">Q", n)
    raise ValueError(f"negative int too large: {value}")


def _cbor_header(major: int, info: int) -> int:
    return (major << 5) | (info & 0x1F)


def _cbor_encode_bytestring(value: bytes) -> bytes:
    n = len(value)
    if n <= 23:
        return bytes([_cbor_header(2, n)]) + value
    if n <= 0xFF:
        return bytes([_cbor_header(2, 24), n]) + value
    if n <= 0xFFFF:
        return bytes([_cbor_header(2, 25)]) + struct.pack(">H", n) + value
    if n <= 0xFFFFFFFF:
        return bytes([_cbor_header(2, 26)]) + struct.pack(">I", n) + value
    raise ValueError(f"bytestring too long: {n}")


def _cbor_encode_textstring(value: str) -> bytes:
    data = value.encode("utf-8")
    n = len(data)
    if n <= 23:
        return bytes([_cbor_header(3, n)]) + data
    if n <= 0xFF:
        return bytes([_cbor_header(3, 24), n]) + data
    if n <= 0xFFFF:
        return bytes([_cbor_header(3, 25)]) + struct.pack(">H", n) + data
    if n <= 0xFFFFFFFF:
        return bytes([_cbor_header(3, 26)]) + struct.pack(">I", n) + data
    raise ValueError(f"textstring too long: {n}")


def _cbor_encode_array(value: list) -> bytes:
    n = len(value)
    head: bytes
    if n <= 23:
        head = bytes([_cbor_header(4, n)])
    elif n <= 0xFF:
        head = bytes([_cbor_header(4, 24), n])
    elif n <= 0xFFFF:
        head = bytes([_cbor_header(4, 25)]) + struct.pack(">H", n)
    elif n <= 0xFFFFFFFF:
        head = bytes([_cbor_header(4, 26)]) + struct.pack(">I", n)
    else:
        raise ValueError(f"array too long: {n}")
    return head + b"".join(cbor_encode(item) for item in value)


def _cbor_encode_map(value: dict) -> bytes:
    """Length-sorted canonical CBOR map (RFC 8949 §4.2.1).

    COSE_Sign1 protected headers MUST be deterministically encodable
    so the same logical header produces the same bytes on every emit.
    We sort by the encoded key form (which is what RFC 8949 §4.2.1
    requires for canonical encoding). The order produced here matches
    what pycose's CoseSign1Message encoder produces for the same keys.
    """
    items = sorted(
        value.items(),
        key=lambda kv: cbor_encode(kv[0]),
    )
    n = len(items)
    head: bytes
    if n <= 23:
        head = bytes([_cbor_header(5, n)])
    elif n <= 0xFF:
        head = bytes([_cbor_header(5, 24), n])
    elif n <= 0xFFFF:
        head = bytes([_cbor_header(5, 25)]) + struct.pack(">H", n)
    elif n <= 0xFFFFFFFF:
        head = bytes([_cbor_header(5, 26)]) + struct.pack(">I", n)
    else:
        raise ValueError(f"map too long: {n}")
    out = head
    for k, v in items:
        out += cbor_encode(k)
        out += cbor_encode(v)
    return out


def cbor_encode(value: Any) -> bytes:
    """Encode a Python value as CBOR. Supports the COSE_Sign1 subset."""
    if isinstance(value, bool):
        # RFC 8949 §3.3: bool is a sub-type of simple values.
        return bytes([0xF5 if value else 0xF4])
    if isinstance(value, int):
        return _cbor_encode_int(value)
    if isinstance(value, bytes):
        return _cbor_encode_bytestring(value)
    if isinstance(value, str):
        return _cbor_encode_textstring(value)
    if isinstance(value, list):
        return _cbor_encode_array(value)
    if isinstance(value, dict):
        return _cbor_encode_map(value)
    if value is None:
        return bytes([0xF6])
    raise TypeError(f"cbor_encode: unsupported type {type(value).__name__}")


class CborDecodeError(ValueError):
    """Raised when CBOR input cannot be decoded."""


def _cbor_read_int_at(data: bytes, pos: int, info: int) -> tuple[int, int]:
    if info <= 23:
        return info, pos
    if info == 24:
        return data[pos], pos + 1
    if info == 25:
        return struct.unpack(">H", data[pos:pos + 2])[0], pos + 2
    if info == 26:
        return struct.unpack(">I", data[pos:pos + 4])[0], pos + 4
    if info == 27:
        return struct.unpack(">Q", data[pos:pos + 8])[0], pos + 8
    raise CborDecodeError(f"unsupported length info {info}")


def _cbor_read_bytestring_at(data: bytes, pos: int, info: int) -> tuple[bytes, int]:
    n, pos = _cbor_read_int_at(data, pos, info)
    if pos + n > len(data):
        raise CborDecodeError("bytestring overruns input")
    return bytes(data[pos:pos + n]), pos + n


def _cbor_read_any(data: bytes, pos: int) -> tuple[Any, int]:
    """Decode one CBOR value at ``pos``; return ``(value, new_pos)``."""
    if pos >= len(data):
        raise CborDecodeError("unexpected end of input")
    initial = data[pos]
    major = initial >> 5
    info = initial & 0x1F
    pos += 1
    if major in (0, 1):
        value, pos = _cbor_read_int_at(data, pos, info)
        if major == 1:
            value = -1 - value
        return value, pos
    if major == 2:
        return _cbor_read_bytestring_at(data, pos, info)
    if major == 3:
        bs, pos = _cbor_read_bytestring_at(data, pos, info)
        return bs.decode("utf-8"), pos
    if major == 4:
        n, pos = _cbor_read_int_at(data, pos, info)
        items: list = []
        for _ in range(n):
            v, pos = _cbor_read_any(data, pos)
            items.append(v)
        return items, pos
    if major == 5:
        n, pos = _cbor_read_int_at(data, pos, info)
        out: dict = {}
        for _ in range(n):
            k, pos = _cbor_read_any(data, pos)
            v, pos = _cbor_read_any(data, pos)
            out[k] = v
        return out, pos
    if major == 7:
        if info in (0x14, 0x15):
            return info == 0x15, pos
        if info == 0x16:
            return None, pos
        raise CborDecodeError(f"unsupported simple value 0x{info:02x}")
    raise CborDecodeError(f"unsupported major type {major}")


def cbor_decode(data: bytes) -> Any:
    """Decode one CBOR value. Returns the Python form.

    Convenience wrapper around :func:`_cbor_read_any` for the common
    "decode the whole thing" case.
    """
    value, _ = _cbor_read_any(data, 0)
    return value


# ---- COSE_Sign1 envelope construction ---------------------------------------


@dataclass
class ScittEnvelope:
    """A SCITT-compatible COSE_Sign1 envelope wrapping one receipt's hash.

    Attributes
    ----------
    protected_b64u : str
        base64url(no padding) encoding of the CBOR-encoded protected
        header map. The protected header carries ``alg`` and
        ``content_type`` and is what gets included in the
        ``Sig_structure`` for signature computation.
    unprotected : dict
        Unprotected header map. Keys are integer labels (or strings when
        emitted in JSON form); values are the corresponding receipt
        fields (kid, operator_key_id, chain_version, receipt_id, etc.).
        The unprotected header is **not** included in the
        ``Sig_structure``; it rides alongside the signature as
        metadata only.
    payload_b64u : str
        base64url(no padding) of the COSE payload: the receipt's
        32-byte ``payload_sha256`` (NOT the 64-char hex).
    signature_b64u : str
        base64url(no padding) of the Ed25519 signature over the
        ``Sig_structure``.
    """

    protected_b64u: str
    unprotected: dict
    payload_b64u: str
    signature_b64u: str


def _b64u_encode(data: bytes) -> str:
    """base64url encoding with no padding (RFC 4648 §5)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    """base64url decode, accepting missing padding."""
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _chain_version_for(receipt: storage.Receipt) -> int:
    """Return the chain version for a receipt, defaulting to v2 for legacy rows."""
    v = (receipt.extra or {}).get(storage.CHAIN_VERSION_KEY)
    if v is None:
        return LEGACY_CHAIN_VERSION
    try:
        return int(v)
    except (TypeError, ValueError):
        return LEGACY_CHAIN_VERSION


def _unprotected_header(receipt: storage.Receipt) -> dict:
    """Build the unprotected COSE header for one receipt.

    Integer keys (matching the LABEL_* constants) are the canonical
    form. The JSON-wrapping step stringifies them per SCITT HTTP
    transport conventions.
    """
    header: dict = {
        LABEL_KID: receipt.key_id,
        LABEL_CHAIN_VERSION: _chain_version_for(receipt),
        LABEL_RECEIPT_ID: int(receipt.id),
        LABEL_PAYLOAD_SHA256: receipt.payload_sha256,
        LABEL_PARENT_ID: -1 if receipt.parent_id is None else int(receipt.parent_id),
        LABEL_MODEL: receipt.model,
        LABEL_TIMESTAMP: receipt.timestamp,
    }
    if receipt.operator_id is not None:
        header[LABEL_OPERATOR_KEY_ID] = receipt.operator_id
    return header


def build_sig_structure(protected_bstr: bytes, payload_bstr: bytes) -> bytes:
    """Build the ``Sig_structure`` (RFC 9052 §4.4) bytes for signing.

    ``Sig_structure = ["Signature1", body_protected, external_aad, payload]``

    The COSE spec uses the literal text string ``"Signature1"`` for
    COSE_Sign1 (not "Signature" — that is the COSE_Sign structure for
    multi-signature cases).
    """
    sig = [
        SIGNATURE_CONTEXT,
        protected_bstr,
        EXTERNAL_AAD,
        payload_bstr,
    ]
    return cbor_encode(sig)


def envelope_for_receipt(receipt: storage.Receipt) -> ScittEnvelope:
    """Build a COSE_Sign1 envelope for one Don't-Lie receipt.

    The signature is over the COSE ``Sig_structure`` wrapping the
    receipt's 32-byte ``payload_sha256`` and the protected header
    bytes. Use :func:`verify_envelope_signature` to check it.
    """
    payload_bytes = bytes.fromhex(receipt.payload_sha256)
    if len(payload_bytes) != 32:
        raise ValueError(
            f"payload_sha256 must be 32 bytes, got {len(payload_bytes)}"
        )

    protected_map = {
        COSE_LABEL_ALG: COSE_ALG_ED25519,
        COSE_LABEL_CONTENT_TYPE: CONTENT_TYPE_RECEIPT_HASH,
    }
    protected_cbor = cbor_encode(protected_map)
    protected_bstr = _cbor_encode_bytestring(protected_cbor)
    payload_bstr = _cbor_encode_bytestring(payload_bytes)

    sig_structure = build_sig_structure(protected_bstr, payload_bstr)

    key = signing.load()
    sig_b64 = signing.sign_bytes(key, sig_structure)
    sig_bytes = base64.b64decode(sig_b64)
    if len(sig_bytes) != 64:
        raise RuntimeError(
            f"Ed25519 signature must be 64 bytes, got {len(sig_bytes)}"
        )

    return ScittEnvelope(
        protected_b64u=_b64u_encode(protected_cbor),
        unprotected=_unprotected_header(receipt),
        payload_b64u=_b64u_encode(payload_bytes),
        signature_b64u=_b64u_encode(sig_bytes),
    )


def envelope_to_json(envelope: ScittEnvelope) -> dict:
    """Render a :class:`ScittEnvelope` as a JSON-wrappable dict.

    Integer labels in the unprotected header are stringified to match
    the SCITT HTTP transport convention used by ``pycose.Sign1.from_json``
    and the SCITT Reference API (SCRAPI). All bstr fields are
    base64url-encoded without padding.
    """
    return {
        "protected": envelope.protected_b64u,
        "unprotected": {
            str(int(k)): v for k, v in envelope.unprotected.items()
        },
        "payload": envelope.payload_b64u,
        "signature": envelope.signature_b64u,
    }


def envelope_from_json(obj: dict) -> ScittEnvelope:
    """Inverse of :func:`envelope_to_json`. Tolerates stringified int keys."""
    unprotected: dict = {}
    for k, v in obj.get("unprotected", {}).items():
        try:
            unprotected[int(k)] = v
        except (TypeError, ValueError):
            unprotected[k] = v
    return ScittEnvelope(
        protected_b64u=str(obj["protected"]),
        unprotected=unprotected,
        payload_b64u=str(obj["payload"]),
        signature_b64u=str(obj["signature"]),
    )


def emit_envelope_cbor(envelope: ScittEnvelope) -> bytes:
    """Emit the raw COSE_Sign1 CBOR 4-element array form.

    Receivers that want the canonical COSE form (Sigstore, pycose's
    ``Sign1.from_cbor``) consume this directly. The CBOR tag for
    COSE_Sign1 (tag 18 per RFC 9052 §4.2) is NOT prepended; add it
    at the consumer if required.
    """
    protected_cbor = _b64u_decode(envelope.protected_b64u)
    payload_bytes = _b64u_decode(envelope.payload_b64u)
    sig_bytes = _b64u_decode(envelope.signature_b64u)
    # Build the unprotected CBOR map directly. Integer keys go through
    # the canonical length-sorted encoder; this is the bytes we hand to
    # the outer array.
    unprotected_cbor = cbor_encode(
        {int(k): v for k, v in envelope.unprotected.items()}
    )
    # The outer array layout is [protected_bstr, unprotected_map, payload_bstr, sig_bstr].
    # Build it by hand so the unprotected map is NOT accidentally wrapped
    # in an extra bstr (cbor_encode of an already-encoded bytes value
    # would re-encode it as a bstr, which is wrong for COSE).
    out = bytearray()
    out.append(_cbor_header(4, 4))  # array of 4
    out += _cbor_encode_bytestring(protected_cbor)
    out += unprotected_cbor
    out += _cbor_encode_bytestring(payload_bytes)
    out += _cbor_encode_bytestring(sig_bytes)
    return bytes(out)


# ---- verification ---------------------------------------------------------


@dataclass
class EnvelopeVerifyResult:
    """Result of verifying one SCITT envelope.

    ``valid`` is True iff the Ed25519 signature checks out. The
    unprotected header is intentionally not part of the signed bytes
    (per COSE), so an attacker could change unprotected fields without
    invalidating the signature. The verifier should cross-reference
    the unprotected fields (kid, receipt_id, payload_sha256) against
    an external source of truth (the don't-lie vault, a witness
    attestation, etc.) to detect that kind of tampering.
    """

    valid: bool
    reason: str = ""
    protected: dict = field(default_factory=dict)
    payload_bytes: bytes = b""
    payload_sha256: str = ""
    key_id: str = ""


def verify_envelope_signature(
    envelope: ScittEnvelope | dict,
    public_key_pem: str | bytes,
) -> EnvelopeVerifyResult:
    """Verify the Ed25519 signature on a COSE_Sign1 envelope.

    The public key is supplied as PEM (matching how
    ``storage._key_material`` and :func:`signing.load_public_key` work).
    Unprotected header cross-checks (kid, payload_sha256 echo, etc.)
    are returned in the result but do not affect ``valid``.
    """
    if isinstance(envelope, dict):
        env = envelope_from_json(envelope)
    else:
        env = envelope

    try:
        pub = signing.load_public_key(public_key_pem)
    except (OSError, ValueError, TypeError) as exc:
        return EnvelopeVerifyResult(
            valid=False,
            reason=f"invalid public key: {exc}",
        )

    try:
        protected_cbor = _b64u_decode(env.protected_b64u)
        protected = cbor_decode(protected_cbor)
        if not isinstance(protected, dict):
            return EnvelopeVerifyResult(
                valid=False,
                reason=f"protected header is not a map: {type(protected).__name__}",
            )
        if protected.get(COSE_LABEL_ALG) != COSE_ALG_ED25519:
            return EnvelopeVerifyResult(
                valid=False,
                reason=f"unsupported alg: {protected.get(COSE_LABEL_ALG)!r}",
                protected=protected,
            )
        payload_bytes = _b64u_decode(env.payload_b64u)
        sig_bytes = _b64u_decode(env.signature_b64u)
    except (CborDecodeError, ValueError, TypeError, base64.binascii.Error) as exc:
        return EnvelopeVerifyResult(
            valid=False,
            reason=f"malformed envelope: {exc}",
        )

    protected_bstr = _cbor_encode_bytestring(protected_cbor)
    payload_bstr = _cbor_encode_bytestring(payload_bytes)
    sig_structure = build_sig_structure(protected_bstr, payload_bstr)

    sig_b64 = base64.b64encode(sig_bytes).decode("ascii")
    ok = signing.verify_bytes(pub, sig_structure, sig_b64)
    if not ok:
        return EnvelopeVerifyResult(
            valid=False,
            reason="Ed25519 signature does not verify",
            protected=protected,
            payload_bytes=payload_bytes,
        )

    payload_sha256 = payload_bytes.hex()
    kid = str(env.unprotected.get(LABEL_KID, ""))
    return EnvelopeVerifyResult(
        valid=True,
        protected=protected,
        payload_bytes=payload_bytes,
        payload_sha256=payload_sha256,
        key_id=kid,
    )


def load_receipt_envelope(receipt_id: int) -> ScittEnvelope:
    """Look up one receipt by id and return its SCITT envelope."""
    receipt = storage.get_receipt(receipt_id)
    if receipt is None:
        raise LookupError(f"receipt {receipt_id} not found")
    return envelope_for_receipt(receipt)


def list_namespace_receipts(
    namespace: str | None = None,
) -> Iterable[storage.Receipt]:
    """Yield receipts in the given namespace, ordered by id (oldest first)."""
    import os
    ns = namespace or os.environ.get("DONTLIE_NAMESPACE", "default")
    conn = storage._connect()
    try:
        rows = conn.execute(
            "SELECT * FROM receipts WHERE namespace = ? ORDER BY id ASC",
            (ns,),
        ).fetchall()
        for row in rows:
            yield storage._row_to_receipt(row)
    finally:
        conn.close()


def build_scitt_bundle(
    namespace: str | None = None,
) -> dict:
    """Build a JSON SCITT bundle of all envelopes in the given namespace.

    The bundle mirrors ``storage.export_bundle``'s shape so the existing
    ``verify`` flow can ingest it, with one addition: every receipt is
    also emitted as a COSE_Sign1 envelope, and the public keys are
    included so any SCITT verifier can check the signatures.
    """
    import os
    ns = namespace or os.environ.get("DONTLIE_NAMESPACE", "default")
    conn = storage._connect()
    try:
        keys, revoked = storage._key_material(conn)
    finally:
        conn.close()

    envelopes_json: list[dict] = []
    receipts: list[dict] = []
    for r in list_namespace_receipts(ns):
        env = envelope_for_receipt(r)
        envelopes_json.append(envelope_to_json(env))
        receipts.append({
            "id": r.id,
            "timestamp": r.timestamp,
            "model": r.model,
            "prompt": r.prompt,
            "response": r.response,
            "parent_id": r.parent_id,
            "key_id": r.key_id,
            "payload_sha256": r.payload_sha256,
            "signature": r.signature,
            "tags": list(r.tags),
            "extra": dict(r.extra),
            "operator_id": r.operator_id,
            "deployer_id": r.deployer_id,
            "system_id": r.system_id,
        })

    return {
        "format": "dontlie-scitt-bundle",
        "version": 1,
        "namespace": ns,
        "count": len(envelopes_json),
        "envelopes": envelopes_json,
        "receipts": receipts,
        "public_keys": keys,
        "revoked_key_ids": sorted(revoked),
    }


def write_scitt_envelope(
    receipt_id: int,
    path: Path | None = None,
) -> Path:
    """Emit a single SCITT envelope (JSON form) to disk.

    Defaults to ``./scitt_envelope_<id>.json`` when no path is given.
    """
    env = load_receipt_envelope(receipt_id)
    out = Path(path) if path is not None else Path(f"scitt_envelope_{receipt_id}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(envelope_to_json(env), sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return out


def write_scitt_bundle(
    path: Path,
    namespace: str | None = None,
) -> int:
    """Emit a SCITT bundle (JSON) to disk. Returns the envelope count."""
    bundle = build_scitt_bundle(namespace=namespace)
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    return int(bundle["count"])


__all__ = [
    "CONTENT_TYPE_RECEIPT_HASH",
    "COSE_ALG_ED25519",
    "LABEL_CHAIN_VERSION",
    "LABEL_KID",
    "LABEL_MODEL",
    "LABEL_OPERATOR_KEY_ID",
    "LABEL_PARENT_ID",
    "LABEL_PAYLOAD_SHA256",
    "LABEL_RECEIPT_ID",
    "LABEL_TIMESTAMP",
    "EnvelopeVerifyResult",
    "ScittEnvelope",
    "build_scitt_bundle",
    "build_sig_structure",
    "cbor_decode",
    "cbor_encode",
    "emit_envelope_cbor",
    "envelope_for_receipt",
    "envelope_from_json",
    "envelope_to_json",
    "load_receipt_envelope",
    "verify_envelope_signature",
    "write_scitt_bundle",
    "write_scitt_envelope",
]
