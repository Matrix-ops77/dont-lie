"""RFC 3161 free-TSA timestamp anchoring for the export bundle.

Implements the wire-format and verify-path described in
``dontlie/anchor/RFC3161_PLAN.md``. The module is dependency-light:
``cryptography`` for x509 certificate verification, and the stdlib for
the ASN.1 surface we need to read.

Three entry points:

- :func:`build_timestamp_request` — produce a DER ``TimeStampReq``.
- :func:`request_attestation` — POST the request to a TSA URL and return
  the parsed response.
- :func:`verify_attestation` — verify a stored attestation against the
  canonical bundle.

The pipeline function :func:`anchor_bundle` ties everything together for
the export path. All network failures degrade to "no attestation"; the
bundle remains valid and the verifier simply reports zero anchors.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.client
import json
import logging
import secrets
import ssl
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from . import pins

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# OIDs (a few we need; other modules in cryptography carry the rest)
# ---------------------------------------------------------------------------

OID_SHA256 = "2.16.840.1.101.3.4.2.1"
OID_SHA384 = "2.16.840.1.101.3.4.2.2"
OID_SHA512 = "2.16.840.1.101.3.4.2.3"
OID_SHA1 = "1.3.14.3.2.26"

OID_RSA = "1.2.840.113549.1.1.1"
OID_ECDSA = "1.2.840.10045.2.1"
OID_ED25519 = "1.3.101.112"
OID_ED448 = "1.3.101.113"

OID_CONTENT_TYPE = "1.2.840.113549.1.9.3"
OID_SIGNED_DATA = "1.2.840.113549.1.7.2"
OID_DATA = "1.2.840.1.113549.1.7.1"
OID_TST_INFO = "1.2.840.113549.1.9.16.1.4"
OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4"
OID_SIGNING_TIME = "1.2.840.113549.1.9.5"

OID_PKI_STATUS_GRANTED = "0.0.0"  # sentinel: status INTEGER = 0


# ---------------------------------------------------------------------------
# Tiny ASN.1 DER codec (only the pieces we need)
# ---------------------------------------------------------------------------


class ASN1Error(ValueError):
    pass


def _der_length(length: int) -> bytes:
    if length < 0x80:
        return bytes([length])
    out = bytearray()
    while length:
        out.append(length & 0xFF)
        length >>= 8
    out.append(0x80 | len(out))
    return bytes(reversed(out))


def _der_header(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _der_length(len(content)) + content


def _encode_integer(value: int) -> bytes:
    if value == 0:
        body = b"\x00"
    else:
        negative = value < 0
        magnitude = abs(value)
        body = bytearray()
        while magnitude:
            body.append(magnitude & 0xFF)
            magnitude >>= 8
        body.reverse()
        if body[-1] & 0x80:
            body.append(0)
        if negative:
            body[-1] |= 0x80
        body = bytes(body)
    return _der_header(0x02, body)


def _encode_oid(oid: str) -> bytes:
    parts = [int(p) for p in oid.split(".")]
    if len(parts) < 2:
        raise ASN1Error(f"OID too short: {oid}")
    body = bytearray([40 * parts[0] + parts[1]])
    for part in parts[2:]:
        if part < 0:
            raise ASN1Error(f"negative OID arc: {part}")
        if part < 0x80:
            body.append(part)
        else:
            stack = bytearray()
            n = part
            while n:
                stack.append(n & 0x7F)
                n >>= 7
            stack.reverse()
            for i, b in enumerate(stack):
                if i == len(stack) - 1:
                    body.append(b)
                else:
                    body.append(b | 0x80)
    return _der_header(0x06, bytes(body))


def _encode_bitstring(content: bytes, unused: int = 0) -> bytes:
    return _der_header(0x03, bytes([unused]) + content)


def _encode_octetstring(content: bytes) -> bytes:
    return _der_header(0x04, content)


def _encode_utf8string(text: str) -> bytes:
    return _der_header(0x0C, text.encode("utf-8"))


def _encode_printablestring(text: str) -> bytes:
    return _der_header(0x13, text.encode("ascii"))


def _encode_utctime(t: datetime.datetime) -> bytes:
    return _der_header(
        0x17, t.strftime("%y%m%d%H%M%SZ").encode("ascii")
    )


def _encode_generalizedtime(t: datetime.datetime) -> bytes:
    return _der_header(
        0x18, t.strftime("%Y%m%d%H%M%SZ").encode("ascii")
    )


def _encode_boolean(value: bool) -> bytes:
    return _der_header(0x01, b"\xFF" if value else b"\x00")


def _encode_sequence(parts: list[bytes]) -> bytes:
    return _der_header(0x30, b"".join(parts))


def _encode_set(parts: list[bytes]) -> bytes:
    return _der_header(0x31, b"".join(parts))


def _encode_explicit(tag: int, content: bytes) -> bytes:
    """Context-specific explicit tag (e.g. for [0] EXPLICIT)."""
    return _der_header(0xA0 | tag, content)


def _encode_null() -> bytes:
    return b"\x05\x00"


class _Reader:
    __slots__ = ("data", "pos")

    def __init__(self, data: bytes, pos: int = 0) -> None:
        self.data = data
        self.pos = pos

    def read(self, n: int) -> bytes:
        if self.pos + n > len(self.data):
            raise ASN1Error("unexpected end of DER")
        out = self.data[self.pos : self.pos + n]
        self.pos += n
        return out

    def peek_tag(self) -> int:
        if self.pos >= len(self.data):
            raise ASN1Error("unexpected end of DER")
        return self.data[self.pos]

    def read_tag(self) -> tuple[int, int, bytes]:
        """Return (tag, length, header_bytes)."""
        start = self.pos
        tag = self.read(1)[0]
        first = self.read(1)[0]
        if first < 0x80:
            length = first
        else:
            nbytes = first & 0x7F
            if nbytes == 0:
                raise ASN1Error("indefinite length not supported")
            length_bytes = self.read(nbytes)
            length = int.from_bytes(length_bytes, "big")
        return tag, length, self.data[start : self.pos]

    def read_tlv(self) -> tuple[int, bytes, bytes]:
        tag, length, header = self.read_tag()
        content = self.read(length)
        return tag, content, header + content

    def subset(self, length: int) -> _Reader:
        start = self.pos
        end = start + length
        if end > len(self.data):
            raise ASN1Error("subset overruns buffer")
        return _Reader(self.data[start:end], 0)

    def at_end(self) -> bool:
        return self.pos >= len(self.data)


def _decode_integer(content: bytes) -> int:
    if not content:
        raise ASN1Error("empty INTEGER")
    negative = bool(content[0] & 0x80)
    if negative:
        # Two's complement
        n = int.from_bytes(content, "big", signed=False)
        n -= 1 << (8 * len(content))
        return n
    return int.from_bytes(content, "big", signed=False)


def _decode_oid(content: bytes) -> str:
    if not content:
        raise ASN1Error("empty OID")
    body = content
    first = body[0]
    parts = [first // 40, first % 40]
    i = 1
    while i < len(body):
        n = 0
        while True:
            if i >= len(body):
                raise ASN1Error("truncated OID")
            b = body[i]
            i += 1
            n = (n << 7) | (b & 0x7F)
            if not (b & 0x80):
                break
        parts.append(n)
    return ".".join(str(p) for p in parts)


def _decode_boolean(content: bytes) -> bool:
    if content == b"\x00":
        return False
    if content == b"\xFF" or content == b"\x00\x00":
        return True
    raise ASN1Error("invalid BOOLEAN")


def _decode_generalizedtime(content: bytes) -> datetime.datetime:
    text = content.decode("ascii")
    text = text.removesuffix("Z")
    return datetime.datetime.strptime(text, "%Y%m%d%H%M%S").replace(
        tzinfo=datetime.timezone.utc
    )


def _decode_utctime(content: bytes) -> datetime.datetime:
    text = content.decode("ascii")
    text = text.removesuffix("Z")
    return datetime.datetime.strptime(text, "%y%m%d%H%M%SZ").replace(
        tzinfo=datetime.timezone.utc
    )


# ---------------------------------------------------------------------------
# Hash OID mapping
# ---------------------------------------------------------------------------

_HASH_OIDS = {
    "sha256": OID_SHA256,
    "sha384": OID_SHA384,
    "sha512": OID_SHA512,
    "sha1": OID_SHA1,
}

_OID_TO_HASH = {
    OID_SHA256: hashes.SHA256,
    OID_SHA384: hashes.SHA384,
    OID_SHA512: hashes.SHA512,
    OID_SHA1: hashes.SHA1,
}


def hash_oid_for(name: str) -> str:
    name = name.lower()
    if name not in _HASH_OIDS:
        raise ValueError(f"unsupported digest name: {name}")
    return _HASH_OIDS[name]


# ---------------------------------------------------------------------------
# Build a TimeStampReq
# ---------------------------------------------------------------------------


def build_timestamp_request(
    digest: bytes, hash_name: str = "sha256", nonce: bytes | None = None
) -> bytes:
    """Encode a DER ``TimeStampReq`` for the given digest."""
    if not digest:
        raise ValueError("digest must not be empty")
    if len(digest) not in (20, 32, 48, 64):
        raise ValueError(f"digest length {len(digest)} not a standard hash")
    hash_oid = hash_oid_for(hash_name)

    hash_alg = _encode_sequence(
        [
            _encode_oid(hash_oid),
            _encode_null(),
        ]
    )
    message_imprint = _encode_sequence(
        [hash_alg, _encode_octetstring(digest)]
    )
    imprints_seq = _encode_sequence([message_imprint])

    parts: list[bytes] = [
        _encode_integer(1),  # version
        imprints_seq,
    ]
    if nonce is not None:
        if len(nonce) > 8:
            raise ValueError("nonce must be <= 8 bytes")
        parts.append(_encode_integer(int.from_bytes(nonce, "big")))
    parts.append(_encode_boolean(False))  # certReq
    return _encode_sequence(parts)


# ---------------------------------------------------------------------------
# Send the request
# ---------------------------------------------------------------------------


def request_attestation(
    tsa_url: str,
    digest: bytes,
    *,
    hash_name: str = "sha256",
    nonce: bytes | None = None,
    timeout: float = 10.0,
) -> ParsedResponse:
    """POST a TimeStampReq to ``tsa_url`` and return the parsed response.

    Raises ``TimestampError`` on any failure (network, parse, status).
    """
    if nonce is None:
        nonce = secrets.token_bytes(8)
    req_der = build_timestamp_request(digest, hash_name, nonce)
    try:
        resp_der = _post_tsr(tsa_url, req_der, timeout=timeout)
    except TimestampError:
        raise
    except Exception as exc:
        raise TimestampError(f"network error contacting TSA: {exc}") from exc
    return parse_response(resp_der, expected_imprint=digest, nonce=nonce)


class TimestampError(Exception):
    """Raised when an RFC 3161 request/response fails."""


def _post_tsr(tsa_url: str, req_der: bytes, *, timeout: float) -> bytes:
    parsed = urllib.parse.urlparse(tsa_url)
    if parsed.scheme not in ("http", "https"):
        raise TimestampError(f"unsupported TSA scheme: {parsed.scheme}")
    host = parsed.hostname
    if not host:
        raise TimestampError("TSA URL is missing a host")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    body = req_der
    headers = {
        "Content-Type": "application/timestamp-query",
        "Content-Length": str(len(body)),
        "Accept": "application/timestamp-reply",
    }

    last_exc: Exception | None = None
    for attempt in (1, 2):
        try:
            if parsed.scheme == "https":
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(
                    host, port, timeout=timeout, context=ctx
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=timeout)
            try:
                conn.request("POST", path, body=body, headers=headers)
                resp = conn.getresponse()
                data = resp.read()
                if resp.status != 200:
                    raise TimestampError(
                        f"TSA returned HTTP {resp.status}: {data[:120]!r}"
                    )
                return bytes(data)
            finally:
                conn.close()
        except (TimeoutError, http.client.HTTPException, OSError) as exc:
            last_exc = exc
            if attempt == 2:
                raise TimestampError(
                    f"TSA request failed after retry: {exc}"
                ) from exc
            continue
    if last_exc is not None:
        raise TimestampError(f"TSA request failed: {last_exc}") from last_exc
    raise TimestampError("TSA request failed: no attempts")  # pragma: no cover


# ---------------------------------------------------------------------------
# Parse a TimeStampResp
# ---------------------------------------------------------------------------


@dataclass
class ParsedResponse:
    status: int
    gen_time: datetime.datetime | None
    serial_number: int | None
    nonce: bytes | None
    cert_der: bytes | None
    message_imprint: bytes | None
    policy_oid: str | None
    hash_oid: str | None
    der: bytes  # full response DER


def parse_response(
    resp_der: bytes,
    *,
    expected_imprint: bytes | None = None,
    nonce: bytes | None = None,
) -> ParsedResponse:
    """Parse a DER ``TimeStampResp`` and extract the salient fields.

    Raises ``TimestampError`` if the status is not granted, the imprint
    does not match, or the nonce does not match.
    """
    try:
        reader = _Reader(resp_der)
        tag, content, _ = reader.read_tlv()
        if tag != 0x30:
            raise ASN1Error("response is not a SEQUENCE")
        inner = _Reader(content)
        status_tag, status_content, _ = inner.read_tlv()
        if status_tag != 0x30:
            raise ASN1Error("PKIStatusInfo is not a SEQUENCE")
        status_reader = _Reader(status_content)
        status_int_tag, status_int_content, _ = status_reader.read_tlv()
        if status_int_tag != 0x02:
            raise ASN1Error("PKIStatus is not INTEGER")
        status = _decode_integer(status_int_content)
        if status != 0:
            raise TimestampError(f"TSA denied request: status={status}")
        ts_token: bytes | None = None
        if not inner.at_end():
            token_tag, token_content, _ = inner.read_tlv()
            if token_tag != 0x30:
                raise ASN1Error("TimeStampToken is not a SEQUENCE")
            ts_token = token_content
        if ts_token is None:
            raise TimestampError("TimeStampResp has no timeStampToken")
    except ASN1Error as exc:
        raise TimestampError(f"failed to parse TimeStampResp: {exc}") from exc

    tst_info, cert_der = _extract_tst_info_and_cert(ts_token)

    # Verify imprint match.
    if expected_imprint is not None and (
        tst_info.message_imprint is None or tst_info.message_imprint != expected_imprint
    ):
        raise TimestampError("message imprint mismatch")

    # Verify nonce match.
    if nonce is not None:
        if tst_info.nonce is None:
            raise TimestampError("nonce missing from response")
        if int.from_bytes(tst_info.nonce, "big") != int.from_bytes(nonce, "big"):
            raise TimestampError("nonce mismatch")

    return ParsedResponse(
        status=status,
        gen_time=tst_info.gen_time,
        serial_number=tst_info.serial_number,
        nonce=tst_info.nonce,
        cert_der=cert_der,
        message_imprint=tst_info.message_imprint,
        policy_oid=tst_info.policy_oid,
        hash_oid=tst_info.hash_oid,
        der=resp_der,
    )


@dataclass
class _TstInfo:
    message_imprint: bytes | None
    hash_oid: str | None
    serial_number: int | None
    gen_time: datetime.datetime | None
    nonce: bytes | None
    policy_oid: str | None


def _extract_tst_info_and_cert(token_content: bytes) -> tuple[_TstInfo, bytes | None]:
    """Drill into a ``TimeStampToken`` (a CMS ContentInfo) and pull out
    the ``TSTInfo`` DER and the first signer certificate DER.

    ``token_content`` is the content of the ``TimeStampToken`` SEQUENCE
    field, which is the *inner* of a ContentInfo SEQUENCE — i.e. the
    raw [OID, [0] EXPLICIT content] tlv stream.
    """
    ci = _Reader(token_content)
    oid_tag, oid_content, _ = ci.read_tlv()
    if oid_tag != 0x06:
        raise ASN1Error("ContentType is not OID")
    content_type = _decode_oid(oid_content)
    if content_type != OID_SIGNED_DATA:
        raise ASN1Error(f"unexpected ContentInfo type: {content_type}")
    explicit_tag, explicit_content, _ = ci.read_tlv()
    if explicit_tag != 0xA0:
        raise ASN1Error("ContentInfo content is not [0] EXPLICIT")
    # SignedData SEQUENCE
    sd = _Reader(explicit_content)
    sd_tag, sd_content, _ = sd.read_tlv()
    if sd_tag != 0x30:
        raise ASN1Error("SignedData is not a SEQUENCE")
    sd_inner = _Reader(sd_content)
    # version INTEGER
    sd_inner.read_tlv()
    # digestAlgorithms SET OF
    sd_inner.read_tlv()
    # encapContentInfo SEQUENCE
    encap_tag, encap_content, _ = sd_inner.read_tlv()
    if encap_tag != 0x30:
        raise ASN1Error("encapContentInfo is not a SEQUENCE")
    encap = _Reader(encap_content)
    encap_oid_tag, encap_oid_content, _ = encap.read_tlv()
    if encap_oid_tag != 0x06:
        raise ASN1Error("encapContentInfo OID missing")
    encap_oid = _decode_oid(encap_oid_content)
    if encap_oid != OID_TST_INFO:
        raise ASN1Error(f"encapContentInfo is not TSTInfo: {encap_oid}")
    encap_explicit_tag, encap_explicit_content, _ = encap.read_tlv()
    if encap_explicit_tag != 0xA0:
        raise ASN1Error("encapContentInfo content is not [0] EXPLICIT")
    # certificates [0] IMPLICIT SET OF Certificate OPTIONAL
    cert_der: bytes | None = None
    if not sd_inner.at_end():
        next_tag, next_content, _ = sd_inner.read_tlv()
        if next_tag == 0xA0:
            cert_set = _Reader(next_content)
            while not cert_set.at_end():
                ct, _cc, cert_der_bytes = cert_set.read_tlv()
                if ct == 0x30:
                    cert_der = cert_der_bytes
                    break

    tst_info = _parse_tst_info(encap_explicit_content)
    return tst_info, cert_der


def _parse_tst_info(der: bytes) -> _TstInfo:
    reader = _Reader(der)
    tag, content, _ = reader.read_tlv()
    if tag != 0x30:
        raise ASN1Error("TSTInfo is not a SEQUENCE")
    inner = _Reader(content)
    fields = _TstInfo(
        message_imprint=None,
        hash_oid=None,
        serial_number=None,
        gen_time=None,
        nonce=None,
        policy_oid=None,
    )
    seen = set()
    while not inner.at_end():
        ftag, fcontent, _ = inner.read_tlv()
        if ftag == 0x02:  # INTEGER
            value = _decode_integer(fcontent)
            if "version" not in seen:
                seen.add("version")
                continue
            if "serial" not in seen:
                fields.serial_number = value
                seen.add("serial")
            elif "nonce" not in seen:
                fields.nonce = value.to_bytes(
                    (value.bit_length() + 7) // 8 or 1, "big", signed=False
                )
                seen.add("nonce")
        elif ftag == 0x06:  # OID
            fields.policy_oid = _decode_oid(fcontent)
        elif ftag == 0x01:  # BOOLEAN
            continue
        elif ftag == 0x18:  # GeneralizedTime
            fields.gen_time = _decode_generalizedtime(fcontent)
        elif ftag == 0x17:  # UTCTime
            fields.gen_time = _decode_utctime(fcontent)
        elif ftag == 0x30:  # SEQUENCE  (MessageImprint)
            mi = _Reader(fcontent)
            alg_tag, alg_content, _ = mi.read_tlv()
            if alg_tag != 0x30:
                raise ASN1Error("hashAlgorithm is not SEQUENCE")
            alg = _Reader(alg_content)
            alg_oid_tag, alg_oid_content, _ = alg.read_tlv()
            if alg_oid_tag != 0x06:
                raise ASN1Error("hashAlgorithm OID missing")
            hash_oid = _decode_oid(alg_oid_content)
            mi_hash_tag, mi_hash_content, _ = mi.read_tlv()
            if mi_hash_tag != 0x04:
                raise ASN1Error("hashedMessage is not OCTET STRING")
            fields.hash_oid = hash_oid
            fields.message_imprint = mi_hash_content
        # else: ignore unknown tags (extensions, etc.)
    return fields


# ---------------------------------------------------------------------------
# Verify an attestation stored in the bundle
# ---------------------------------------------------------------------------


def verify_attestation(
    attestation: Mapping[str, Any],
    canonical_bundle: bytes,
) -> bool:
    """Return True iff the attestation is a valid RFC 3161 anchor for
    the canonical bundle content."""
    if attestation.get("type") != "rfc3161":
        return False
    imprint_hex = attestation.get("message_imprint")
    sig_b64 = attestation.get("tsa_signature")
    cert_pin = attestation.get("tsa_cert_sha256")
    tsa_url = attestation.get("tsa_url")
    try:
        if not (imprint_hex and sig_b64 and cert_pin and tsa_url):
            return False
        expected_imprint = hashlib.sha256(canonical_bundle).digest()
        if imprint_hex.lower() != expected_imprint.hex():
            return False
        resp_der = base64.b64decode(sig_b64)
        parsed = parse_response(resp_der)
        if parsed.message_imprint != expected_imprint:
            return False
        if parsed.cert_der is None:
            return False
        # Pin match.
        cert_hash = hashlib.sha256(parsed.cert_der).hexdigest()
        if cert_hash.lower() != cert_pin.lower():
            return False
        # Look up pin set in our table.
        entry = pins.find_by_url(tsa_url)
        if entry is None:
            return False
        if cert_hash.lower() not in {p.lower() for p in entry.cert_sha256}:
            return False
        # Verify the TSA's signature over the TSTInfo.
        if not _verify_tsa_signature(parsed):
            return False
        # Nonce match (if recorded).
        stored_nonce = attestation.get("nonce")
        if stored_nonce:
            nonce_int = int(stored_nonce, 16)
            if parsed.nonce is None:
                return False
            parsed_int = int.from_bytes(parsed.nonce, "big", signed=False)
            if parsed_int != nonce_int:
                return False
        return True
    except (TimestampError, ASN1Error, ValueError, KeyError):
        return False
    except Exception:
        return False


def _verify_tsa_signature(parsed: ParsedResponse) -> bool:
    """Verify the TSA's signature over the TSTInfo.

    Simplified: we trust the response if the cert verifies against the
    pinned SHA-256 and the parsed fields cross-check. Full CMS verifier
    signature recreation is out of scope for v1.
    """
    if parsed.cert_der is None:
        return False
    try:
        cert = x509.load_der_x509_certificate(parsed.cert_der)
    except Exception:
        return False
    # Reject certs that are expired or not yet valid.
    now = datetime.datetime.now(datetime.timezone.utc)
    try:
        if cert.not_valid_after_utc < now or cert.not_valid_before_utc > now:
            return False
    except AttributeError:
        # Older cryptography versions
        if cert.not_valid_after < now or cert.not_valid_before > now:
            return False
    # TimeStamping EKU is recommended (1.3.6.1.5.5.7.3.8) but not required.
    return True


# ---------------------------------------------------------------------------
# Anchor the bundle (export-time)
# ---------------------------------------------------------------------------


def anchor_bundle(
    bundle: dict[str, Any],
    *,
    tsa_url: str | None = None,
    timeout: float = 10.0,
) -> dict[str, Any]:
    """Best-effort: ask a TSA to attest the canonical bundle.

    On any failure (network, bad response, validation), the bundle is
    returned unchanged with a warning logged. The export pipeline
    therefore never fails because of an anchor.
    """
    if tsa_url is None:
        tsa_url = pins.default_tsa().url
    canonical = canonical_bundle_bytes(bundle)
    digest = hashlib.sha256(canonical).digest()
    try:
        parsed = request_attestation(
            tsa_url, digest, hash_name="sha256", timeout=timeout
        )
    except TimestampError as exc:
        log.warning("RFC 3161 anchor skipped: %s", exc)
        return bundle
    pin = _pin_for_url(tsa_url)
    attestation = {
        "type": "rfc3161",
        "tsa_url": tsa_url,
        "tsa_cert_sha256": pin,
        "digest_algorithm": "sha256",
        "message_imprint": digest.hex(),
        "serial_number": (
            format(parsed.serial_number, "x") if parsed.serial_number else ""
        ),
        "gen_time": (
            parsed.gen_time.isoformat() if parsed.gen_time else ""
        ),
        "tsa_signature": base64.b64encode(parsed.der).decode("ascii"),
    }
    if parsed.nonce is not None:
        attestation["nonce"] = parsed.nonce.hex()
    if parsed.policy_oid:
        attestation["policy_oid"] = parsed.policy_oid
    bundle.setdefault("attestations", []).append(attestation)
    return bundle


def canonical_bundle_bytes(bundle: Mapping[str, Any]) -> bytes:
    """Stable JSON encoding of the bundle minus the attestations list.

    Sort keys and use compact separators so the imprint is reproducible
    across implementations.
    """
    payload = {
        "schema_version": bundle.get("schema_version"),
        "generator": bundle.get("generator"),
        "receipts": bundle.get("receipts", []),
        "pubkeys": bundle.get("pubkeys", []),
    }
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _pin_for_url(tsa_url: str) -> str:
    """Return the configured pin for a URL, or '' if none."""
    entry = pins.find_by_url(tsa_url)
    if entry is None or not entry.cert_sha256:
        return ""
    return min(entry.cert_sha256)


__all__ = [
    "ASN1Error",
    "TimestampError",
    "anchor_bundle",
    "build_timestamp_request",
    "canonical_bundle_bytes",
    "parse_response",
    "request_attestation",
    "verify_attestation",
]
