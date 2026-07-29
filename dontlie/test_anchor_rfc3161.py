"""Offline tests for the RFC 3161 anchor module.

Three classes of tests:

1. **ASN.1 + request build** — pure encoding, no network, no keypair.
2. **Anchor / verify round-trip** — builds a synthetic
   ``TimeStampResp`` from a self-signed cert, anchors a bundle, then
   verifies it. Network is bypassed by mocking the HTTP POST.
3. **Failure paths** — wrong nonce, wrong imprint, wrong cert pin,
   network failure.

A live-network integration test (skipped when offline) demands a real
TSA response and pins its cert fingerprint on first run.
"""

from __future__ import annotations

import base64
import datetime
import hashlib
import http.client
import json
import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

import dontlie.anchor as anchor
from dontlie.anchor import (
    TimestampError,
    anchor_bundle,
    build_timestamp_request,
    canonical_bundle_bytes,
    default_tsa,
    parse_response,
    request_attestation,
    verify_attestation,
)
from dontlie.anchor import pins as anchor_pins
from dontlie.anchor import rfc3161 as anchor_rfc3161


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_self_signed_cert() -> bytes:
    """Return DER-encoded self-signed cert valid for ~10 years."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "test-tsa")]
    )
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.DER)


def _build_minimal_tsresp(
    cert_der: bytes, imprint: bytes, nonce: bytes | None
) -> bytes:
    """Build a minimal DER TimeStampResp wrapping a TSTInfo.

    The TSTInfo is wrapped in a ContentInfo + SignedData structure with
    one certificate, but the signature is a stand-in (zeros). The verify
    path does not enforce signature recreation in v1 (see
    ``_verify_tsa_signature``); it only checks the pin, imprint, nonce,
    and cert validity window.
    """
    # Build TSTInfo
    hash_alg = anchor_rfc3161._encode_sequence(
        [anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SHA256), anchor_rfc3161._encode_null()]
    )
    message_imprint = anchor_rfc3161._encode_sequence(
        [hash_alg, anchor_rfc3161._encode_octetstring(imprint)]
    )
    serial_int = 12345
    tst_info_parts: list[bytes] = [
        anchor_rfc3161._encode_integer(1),
        message_imprint,
        anchor_rfc3161._encode_integer(serial_int),
        anchor_rfc3161._encode_generalizedtime(
            datetime.datetime(2026, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
        ),
    ]
    if nonce is not None:
        tst_info_parts.append(
            anchor_rfc3161._encode_integer(int.from_bytes(nonce, "big"))
        )
    tst_info = anchor_rfc3161._encode_sequence(tst_info_parts)

    # encapContentInfo: SEQUENCE { OID(id-tstInfo), [0] EXPLICIT TSTInfo }
    encap = anchor_rfc3161._encode_sequence(
        [
            anchor_rfc3161._encode_oid(anchor_rfc3161.OID_TST_INFO),
            anchor_rfc3161._encode_explicit(0, tst_info),
        ]
    )
    # digestAlgorithms SET OF
    digest_algs = anchor_rfc3161._encode_set(
        [
            anchor_rfc3161._encode_sequence(
                [
                    anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SHA256),
                    anchor_rfc3161._encode_null(),
                ]
            )
        ]
    )
    # certificates [0] IMPLICIT SET OF Certificate
    certs = anchor_rfc3161._encode_explicit(0, cert_der)
    # signerInfos SET OF SignerInfo (placeholder; not parsed by verify)
    signer_info = anchor_rfc3161._encode_sequence(
        [
            anchor_rfc3161._encode_integer(1),
            anchor_rfc3161._encode_sequence(
                [
                    anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SHA256),
                    anchor_rfc3161._encode_null(),
                ]
            ),
            anchor_rfc3161._encode_sequence(
                [anchor_rfc3161._encode_oid(anchor_rfc3161.OID_RSA)]
            ),
            anchor_rfc3161._encode_sequence(
                [anchor_rfc3161._encode_octetstring(b"\x00" * 32)]
            ),
        ]
    )
    signer_infos = anchor_rfc3161._encode_set([signer_info])
    signed_data = anchor_rfc3161._encode_sequence(
        [
            anchor_rfc3161._encode_integer(1),
            digest_algs,
            encap,
            certs,
            signer_infos,
        ]
    )
    content_info = anchor_rfc3161._encode_sequence(
        [
            anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SIGNED_DATA),
            anchor_rfc3161._encode_explicit(0, signed_data),
        ]
    )
    # TimeStampResp: SEQUENCE { PKIStatusInfo, TimeStampToken }
    pki_status_info = anchor_rfc3161._encode_sequence(
        [anchor_rfc3161._encode_integer(0)]  # granted
    )
    return anchor_rfc3161._encode_sequence(
        [pki_status_info, content_info]
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fake_post_tsr(resp_der: bytes):
    """Return a stand-in for ``_post_tsr`` that yields ``resp_der``."""

    def fake_post(tsa_url: str, req_der: bytes, *, timeout: float):
        return resp_der

    return fake_post


# ---------------------------------------------------------------------------
# ASN.1 / TimeStampReq building
# ---------------------------------------------------------------------------


class TimeStampReqBuildTest(unittest.TestCase):
    def test_build_request_with_default_sha256(self) -> None:
        req = build_timestamp_request(b"\x00" * 32, "sha256")
        self.assertGreater(len(req), 0)
        self.assertEqual(req[0], 0x30)  # SEQUENCE

    def test_build_request_with_nonce(self) -> None:
        req = build_timestamp_request(b"\x00" * 32, "sha256", nonce=b"\x01\x02\x03\x04\x05\x06\x07\x08")
        self.assertGreater(len(req), 0)

    def test_build_request_rejects_short_digest(self) -> None:
        with self.assertRaises(ValueError):
            build_timestamp_request(b"\x00" * 10, "sha256")

    def test_build_request_rejects_oversized_nonce(self) -> None:
        with self.assertRaises(ValueError):
            build_timestamp_request(b"\x00" * 32, "sha256", nonce=b"\x00" * 16)

    def test_build_request_rejects_empty_digest(self) -> None:
        with self.assertRaises(ValueError):
            build_timestamp_request(b"", "sha256")


# ---------------------------------------------------------------------------
# Pins
# ---------------------------------------------------------------------------


class PinTableTest(unittest.TestCase):
    def setUp(self) -> None:
        # Snapshot any runtime-set pins so tests are hermetic.
        self._snap = {
            name: set(entry.cert_sha256)
            for name, entry in {
                "freetsa": anchor_pins.get_entry("freetsa"),
                "digistamp": anchor_pins.get_entry("digistamp"),
                "sectigo": anchor_pins.get_entry("sectigo"),
            }.items()
        }

    def tearDown(self) -> None:
        for name, snap in self._snap.items():
            anchor_pins.clear_pins(name)
            for pin in snap:
                anchor_pins.set_pin(name, pin)

    def test_default_tsa_is_freetsa(self) -> None:
        self.assertEqual(default_tsa().url, "https://freetsa.org/tsr")

    def test_set_pin_adds_and_persists(self) -> None:
        cert_der = _make_self_signed_cert()
        anchor_pins.set_pin("freetsa", cert_der)
        entry = anchor_pins.get_entry("freetsa")
        self.assertIn(_sha256_hex(cert_der), {p.lower() for p in entry.cert_sha256})

    def test_set_pin_rejects_invalid_hex(self) -> None:
        with self.assertRaises(ValueError):
            anchor_pins.set_pin("freetsa", "not-a-pin")

    def test_find_by_url(self) -> None:
        entry = anchor_pins.find_by_url("https://freetsa.org/tsr")
        self.assertIsNotNone(entry)
        self.assertEqual(entry.name, "freetsa")

    def test_find_by_url_unknown(self) -> None:
        self.assertIsNone(anchor_pins.find_by_url("https://example.com/tsr"))


# ---------------------------------------------------------------------------
# Anchor / verify round-trip (offline, mocked HTTP)
# ---------------------------------------------------------------------------


class AnchorRoundTripTest(unittest.TestCase):
    def setUp(self) -> None:
        self._sure_pinname = "freetsa"
        self._original_pins = set(
            anchor_pins.get_entry(self._sure_pinname).cert_sha256
        )
        self.cert_der = _make_self_signed_cert()
        self.pin = _sha256_hex(self.cert_der)
        anchor_pins.set_pin(self._sure_pinname, self.pin)

    def tearDown(self) -> None:
        anchor_pins.clear_pins(self._sure_pinname)
        for pin in self._original_pins:
            anchor_pins.set_pin(self._sure_pinname, pin)

    def test_anchor_bundle_then_verify_attestation(self) -> None:
        bundle = {
            "schema_version": 1,
            "generator": "test",
            "receipts": [{"id": 1, "payload_sha256": "abc"}],
            "pubkeys": [],
        }
        canonical = canonical_bundle_bytes(bundle)
        imprint = hashlib.sha256(canonical).digest()
        # Build a synthetic response with the nonce the request will use.
        # Mock both _post_tsr AND request_attestation's nonce generation
        # so the test is deterministic.
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        resp = _build_minimal_tsresp(self.cert_der, imprint, nonce)

        posted = {}
        real_request = request_attestation

        def fake_request(tsa_url, digest, *, hash_name="sha256", nonce=None, timeout=10.0):
            posted["nonce"] = nonce
            from dataclasses import replace
            parsed = parse_response(resp, expected_imprint=digest, nonce=nonce)
            return parsed

        with patch.object(anchor_rfc3161, "request_attestation", fake_request):
            anchored = anchor_bundle(bundle, tsa_url="https://freetsa.org/tsr")
        self.assertIn("attestations", anchored)
        self.assertEqual(len(anchored["attestations"]), 1)
        att = anchored["attestations"][0]
        self.assertEqual(att["type"], "rfc3161")
        self.assertEqual(att["tsa_cert_sha256"], self.pin)
        self.assertEqual(att["message_imprint"], imprint.hex())
        # Verify succeeds.
        self.assertTrue(verify_attestation(att, canonical))

    def test_anchor_bundle_silent_skip_on_network_error(self) -> None:
        bundle = {"schema_version": 1, "receipts": [], "pubkeys": []}

        def fake_post_fail(*args, **kwargs):
            raise TimestampError("network unreachable")

        with patch.object(anchor_rfc3161, "_post_tsr", fake_post_fail):
            anchored = anchor_bundle(bundle, tsa_url="https://freetsa.org/tsr")
        # No attestation added, bundle still valid.
        self.assertNotIn("attestations", anchored)
        self.assertEqual(anchored["receipts"], [])


# ---------------------------------------------------------------------------
# Failure paths
# ---------------------------------------------------------------------------


class FailurePathTest(unittest.TestCase):
    def setUp(self) -> None:
        self._original_pins = set(anchor_pins.get_entry("freetsa").cert_sha256)
        self.cert_der = _make_self_signed_cert()
        self.pin = _sha256_hex(self.cert_der)
        anchor_pins.set_pin("freetsa", self.pin)

    def tearDown(self) -> None:
        anchor_pins.clear_pins("freetsa")
        for pin in self._original_pins:
            anchor_pins.set_pin("freetsa", pin)

    def test_verify_fails_when_imprint_mismatch(self) -> None:
        bundle = {"schema_version": 1, "receipts": [], "pubkeys": []}
        canonical = canonical_bundle_bytes(bundle)
        bad_imprint = hashlib.sha256(b"tampered").digest()
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        resp = _build_minimal_tsresp(self.cert_der, bad_imprint, nonce)
        parsed = parse_response(resp)
        att = {
            "type": "rfc3161",
            "tsa_url": "https://freetsa.org/tsr",
            "tsa_cert_sha256": self.pin,
            "digest_algorithm": "sha256",
            "message_imprint": bad_imprint.hex(),
            "tsa_signature": base64.b64encode(resp).decode("ascii"),
        }
        self.assertFalse(verify_attestation(att, canonical))

    def test_verify_fails_when_nonce_mismatch(self) -> None:
        bundle = {"schema_version": 1, "receipts": [], "pubkeys": []}
        canonical = canonical_bundle_bytes(bundle)
        imprint = hashlib.sha256(canonical).digest()
        # Build a response with nonce A, but record nonce B in the
        # attestation; verify must reject.
        nonce_a = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        nonce_b_int = int.from_bytes(b"\x10\x20\x30\x40\x50\x60\x70\x80", "big")
        resp_parts: list[bytes] = [
            anchor_rfc3161._encode_integer(1),
            anchor_rfc3161._encode_sequence(
                [
                    anchor_rfc3161._encode_sequence(
                        [
                            anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SHA256),
                            anchor_rfc3161._encode_null(),
                        ]
                    ),
                    anchor_rfc3161._encode_octetstring(imprint),
                ]
            ),
            anchor_rfc3161._encode_integer(12345),
            anchor_rfc3161._encode_generalizedtime(
                datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
            ),
            anchor_rfc3161._encode_integer(nonce_b_int),
        ]
        tst_info = anchor_rfc3161._encode_sequence(resp_parts)
        encap = anchor_rfc3161._encode_sequence(
            [
                anchor_rfc3161._encode_oid(anchor_rfc3161.OID_TST_INFO),
                anchor_rfc3161._encode_explicit(0, tst_info),
            ]
        )
        digest_algs = anchor_rfc3161._encode_set(
            [
                anchor_rfc3161._encode_sequence(
                    [
                        anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SHA256),
                        anchor_rfc3161._encode_null(),
                    ]
                )
            ]
        )
        certs = anchor_rfc3161._encode_explicit(0, self.cert_der)
        signer_info = anchor_rfc3161._encode_sequence(
            [
                anchor_rfc3161._encode_integer(1),
                anchor_rfc3161._encode_sequence(
                    [
                        anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SHA256),
                        anchor_rfc3161._encode_null(),
                    ]
                ),
                anchor_rfc3161._encode_sequence(
                    [anchor_rfc3161._encode_oid(anchor_rfc3161.OID_RSA)]
                ),
                anchor_rfc3161._encode_sequence(
                    [anchor_rfc3161._encode_octetstring(b"\x00" * 32)]
                ),
            ]
        )
        signed_data = anchor_rfc3161._encode_sequence(
            [
                anchor_rfc3161._encode_integer(1),
                digest_algs,
                encap,
                certs,
                anchor_rfc3161._encode_set([signer_info]),
            ]
        )
        content_info = anchor_rfc3161._encode_sequence(
            [
                anchor_rfc3161._encode_oid(anchor_rfc3161.OID_SIGNED_DATA),
                anchor_rfc3161._encode_explicit(0, signed_data),
            ]
        )
        resp = anchor_rfc3161._encode_sequence(
            [
                anchor_rfc3161._encode_sequence(
                    [anchor_rfc3161._encode_integer(0)]
                ),
                content_info,
            ]
        )
        att = {
            "type": "rfc3161",
            "tsa_url": "https://freetsa.org/tsr",
            "tsa_cert_sha256": self.pin,
            "digest_algorithm": "sha256",
            "message_imprint": imprint.hex(),
            "nonce": nonce_a.hex(),
            "tsa_signature": base64.b64encode(resp).decode("ascii"),
        }
        self.assertFalse(verify_attestation(att, canonical))

    def test_verify_fails_when_cert_not_pinned(self) -> None:
        anchor_pins.clear_pins("freetsa")
        bundle = {"schema_version": 1, "receipts": [], "pubkeys": []}
        canonical = canonical_bundle_bytes(bundle)
        imprint = hashlib.sha256(canonical).digest()
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        resp = _build_minimal_tsresp(self.cert_der, imprint, nonce)
        att = {
            "type": "rfc3161",
            "tsa_url": "https://freetsa.org/tsr",
            "tsa_cert_sha256": self.pin,
            "digest_algorithm": "sha256",
            "message_imprint": imprint.hex(),
            "tsa_signature": base64.b64encode(resp).decode("ascii"),
        }
        self.assertFalse(verify_attestation(att, canonical))

    def test_verify_fails_when_attestation_type_wrong(self) -> None:
        self.assertFalse(verify_attestation({"type": "opentimestamps"}, b""))

    def test_verify_fails_when_canonical_is_tampered(self) -> None:
        bundle = {"schema_version": 1, "receipts": [], "pubkeys": []}
        canonical = canonical_bundle_bytes(bundle)
        nonce = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        resp = _build_minimal_tsresp(
            self.cert_der, hashlib.sha256(canonical).digest(), nonce
        )
        att = {
            "type": "rfc3161",
            "tsa_url": "https://freetsa.org/tsr",
            "tsa_cert_sha256": self.pin,
            "digest_algorithm": "sha256",
            "message_imprint": hashlib.sha256(canonical).hexdigest(),
            "tsa_signature": base64.b64encode(resp).decode("ascii"),
        }
        # Verify with a different canonical bundle → mismatch.
        tampered_canonical = canonical_bundle_bytes(
            {"schema_version": 1, "receipts": [{"injected": True}], "pubkeys": []}
        )
        self.assertFalse(verify_attestation(att, tampered_canonical))

    def test_parse_response_rejects_bad_status(self) -> None:
        bad_resp = anchor_rfc3161._encode_sequence(
            [
                anchor_rfc3161._encode_sequence(
                    [anchor_rfc3161._encode_integer(2)]  # rejection
                )
            ]
        )
        with self.assertRaises(TimestampError):
            parse_response(bad_resp)


# ---------------------------------------------------------------------------
# Live-network integration test (skipped without network or live TSA)
# ---------------------------------------------------------------------------


@unittest.skipUnless(
    os.environ.get("DONTLIE_LIVE_RFC3161") == "1",
    "live TSA integration test disabled; set DONTLIE_LIVE_RFC3161=1 to run",
)
class LiveFreeTSAIntegrationTest(unittest.TestCase):
    """Demands a real FreeTSA response and pins the cert on first run.

    Skipped by default. To run execute:
        DONTLIE_LIVE_RFC3161=1 python3 -m unittest dontlie.test_anchor_rfc3161
    """

    def test_live_freetsa_response_is_anchored(self) -> None:
        bundle = {"schema_version": 1, "receipts": [], "pubkeys": []}
        canonical = canonical_bundle_bytes(bundle)
        imprint = hashlib.sha256(canonical).digest()
        try:
            parsed = request_attestation(
                "https://freetsa.org/tsr", imprint, hash_name="sha256"
            )
        except (TimestampError, OSError) as exc:
            self.skipTest(f"network unavailable: {exc}")
        # Pin the cert so verify can match.
        if parsed.cert_der is None:
            self.skipTest("TSA response did not include a cert")
        anchor_pins.set_pin("freetsa", parsed.cert_der)
        try:
            att = {
                "type": "rfc3161",
                "tsa_url": "https://freetsa.org/tsr",
                "tsa_cert_sha256": _sha256_hex(parsed.cert_der),
                "digest_algorithm": "sha256",
                "message_imprint": imprint.hex(),
                "tsa_signature": base64.b64encode(parsed.der).decode("ascii"),
            }
            self.assertTrue(verify_attestation(att, canonical))
        finally:
            anchor_pins.clear_pins("freetsa")


if __name__ == "__main__":
    unittest.main()
