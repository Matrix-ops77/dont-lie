"""Tests for the SCITT-compatible COSE_Sign1 envelope module.

Covers the five acceptance criteria from the integration brief:
1. COSE_Sign1 structure parses correctly (alg=-8, signature length, payload length).
2. Ed25519 signature re-verifies against the receipt's public key from key_history.
3. The bundle format round-trips three receipts.
4. Tamper detection — modifying the payload bytes invalidates the signature.
5. Both v2 (legacy) and v3 (Article 12(3) identity fields) receipts produce
   envelopes that verify correctly.

Plus an extra check that the unprotected header carries the required
Don't-Lie-specific labels (kid, operator_key_id, chain_version).
"""
from __future__ import annotations

import copy
import os
import tempfile
import unittest
from pathlib import Path

from dontlie import scitt, storage
from dontlie import sign as signing


def _isolated_workspace(prefix: str = "dontlie-scitt-") -> tuple[Path, tempfile.TemporaryDirectory]:
    """Point the storage and signing modules at a fresh scratch directory.

    This is the SCITT test isolation helper. It mutates the *module-level*
    paths that ``dontlie.storage`` and ``dontlie.signing`` consult at
    every call (these are read at import time and cached), and it
    exposes a ``restore()`` callable on the returned ``temp`` object that
    every test's ``tearDown`` MUST call before the next test runs.
    Without that, ``storage.DB_PATH`` stays bound to the (now-deleted)
    tempdir and the next test's ``storage.append`` creates a fresh empty
    SQLite file at the deleted path — which is how the production vault
    got wiped in the original v0.3.0 commit.
    """
    temp = tempfile.TemporaryDirectory(prefix=prefix)
    root = Path(temp.name)
    saved = {
        "DB_PATH": storage.DB_PATH,
        "KEY_DIR": signing.KEY_DIR,
        "PRIVATE_FILE": signing.PRIVATE_FILE,
        "PUBLIC_FILE": signing.PUBLIC_FILE,
        "KEY_ID_FILE": signing.KEY_ID_FILE,
    }

    def restore() -> None:
        storage.DB_PATH = saved["DB_PATH"]
        signing.KEY_DIR = saved["KEY_DIR"]
        signing.PRIVATE_FILE = saved["PRIVATE_FILE"]
        signing.PUBLIC_FILE = saved["PUBLIC_FILE"]
        signing.KEY_ID_FILE = saved["KEY_ID_FILE"]

    # Attach restore() to the tempdir handle so tearDown finds it.
    temp.restore = restore
    temp._dontlie_restore = restore  # belt + braces

    signing.KEY_DIR = root / "keys"
    signing.PRIVATE_FILE = signing.KEY_DIR / "dontlie.key"
    signing.PUBLIC_FILE = signing.KEY_DIR / "dontlie.pub"
    signing.KEY_ID_FILE = signing.KEY_ID_FILE  # placeholder; corrected below
    signing.KEY_ID_FILE = signing.KEY_DIR / "key_id"
    storage.DB_PATH = root / "vault.db"
    signing.generate()
    storage.init()
    # Wipe the receipts table so each test starts at id=1. The key is shared
    # with the signature/verification tests that follow.
    conn = storage._connect()
    try:
        conn.execute("DELETE FROM receipts")
        conn.execute("DELETE FROM key_history")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
        conn.commit()
    finally:
        conn.close()
    return root, temp


class ScittEnvelopeStructureTest(unittest.TestCase):
    """Test 1: parse the COSE_Sign1 structure and validate the protected header."""

    def setUp(self) -> None:
        self.root, self._temp = _isolated_workspace()
        self.receipt = storage.append("gpt-4o-mini", "p1", "r1")
        self.envelope = scitt.envelope_for_receipt(self.receipt)
        self.obj = scitt.envelope_to_json(self.envelope)

    def tearDown(self) -> None:
        self._temp.restore()
        self._temp.cleanup()

    def test_envelope_has_required_top_level_keys(self) -> None:
        for key in ("protected", "unprotected", "payload", "signature"):
            self.assertIn(key, self.obj, f"envelope missing {key!r}")

    def test_protected_header_parses_to_cose_sign1_map(self) -> None:
        ph_b64u = self.obj["protected"]
        ph_bytes = scitt._b64u_decode(ph_b64u)
        parsed = scitt.cbor_decode(ph_bytes)
        self.assertIsInstance(parsed, dict)
        # COSE common label 1 = alg. Ed25519 = -8.
        self.assertEqual(parsed.get(1), scitt.COSE_ALG_ED25519)
        self.assertEqual(parsed.get(1), -8)
        # COSE common label 3 = content type. Our content type is the
        # raw 32-byte receipt hash.
        self.assertEqual(parsed.get(3), scitt.CONTENT_TYPE_RECEIPT_HASH)

    def test_signature_is_64_bytes(self) -> None:
        sig = scitt._b64u_decode(self.obj["signature"])
        self.assertEqual(len(sig), 64, "Ed25519 signature must be 64 bytes")

    def test_payload_is_32_bytes_sha256(self) -> None:
        payload = scitt._b64u_decode(self.obj["payload"])
        self.assertEqual(len(payload), 32, "COSE payload must be 32 bytes")
        self.assertEqual(payload.hex(), self.receipt.payload_sha256)

    def test_cbor_4element_array_form_is_emit_ready(self) -> None:
        cbor = scitt.emit_envelope_cbor(self.envelope)
        # COSE_Sign1 = 4-element array; outer CBOR head is 0x84 (array of 4).
        self.assertEqual(cbor[0], 0x84, "COSE_Sign1 must be a 4-element array")
        # Round-trip through cbor_decode to confirm it parses.
        parsed = scitt.cbor_decode(cbor)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 4)
        # Element 0: protected bstr (the protected CBOR map wrapped in a bstr).
        # Element 1: unprotected map (decoded as dict — not a bstr).
        # Element 2: payload bstr (32 bytes).
        # Element 3: signature bstr (64 bytes).
        protected_bstr, unprotected, payload_bstr, sig_bstr = parsed
        self.assertIsInstance(protected_bstr, bytes)
        self.assertIsInstance(unprotected, dict)
        self.assertIsInstance(payload_bstr, bytes)
        self.assertIsInstance(sig_bstr, bytes)
        self.assertEqual(len(payload_bstr), 32)
        self.assertEqual(len(sig_bstr), 64)


class ScittSignatureVerificationTest(unittest.TestCase):
    """Test 2: re-verify the envelope signature against key_history public key."""

    def setUp(self) -> None:
        self.root, self._temp = _isolated_workspace()
        self.receipt = storage.append("gpt-4o-mini", "p1", "r1")
        self.envelope = scitt.envelope_for_receipt(self.receipt)
        self.obj = scitt.envelope_to_json(self.envelope)
        # Pull the public key out of the same key_history the production
        # verifier would use.
        conn = storage._connect()
        try:
            keys, _ = storage._key_material(conn)
        finally:
            conn.close()
        self.public_key_pem = keys[self.receipt.key_id]

    def tearDown(self) -> None:
        self._temp.restore()
        self._temp.cleanup()

    def test_signature_verifies_against_public_key(self) -> None:
        result = scitt.verify_envelope_signature(self.envelope, self.public_key_pem)
        self.assertTrue(result.valid, f"verify failed: {result.reason}")
        self.assertEqual(result.payload_sha256, self.receipt.payload_sha256)
        self.assertEqual(result.key_id, self.receipt.key_id)

    def test_signature_verifies_via_json_form(self) -> None:
        # The CLI produces JSON-wrappable envelopes; the verifier must
        # accept that form too.
        result = scitt.verify_envelope_signature(self.obj, self.public_key_pem)
        self.assertTrue(result.valid, f"json-form verify failed: {result.reason}")

    def test_wrong_public_key_fails_verification(self) -> None:
        # Generate a different key, use its public key — verify must reject.
        other_kp = signing.Ed25519PrivateKey.generate()
        other_pem = signing.public_key_to_pem(other_kp.public_key())
        result = scitt.verify_envelope_signature(self.envelope, other_pem)
        self.assertFalse(result.valid)
        self.assertIn("does not verify", result.reason)


class ScittBundleTest(unittest.TestCase):
    """Test 3: the SCITT bundle format works with three receipts."""

    def setUp(self) -> None:
        self.root, self._temp = _isolated_workspace()
        self.receipts = [
            storage.append("gpt-4o-mini", f"p{i}", f"r{i}") for i in range(3)
        ]
        self.bundle = scitt.build_scitt_bundle()

    def tearDown(self) -> None:
        self._temp.restore()
        self._temp.cleanup()

    def test_bundle_has_three_envelopes(self) -> None:
        self.assertEqual(self.bundle["count"], 3)
        self.assertEqual(len(self.bundle["envelopes"]), 3)
        self.assertEqual(len(self.bundle["receipts"]), 3)

    def test_bundle_format_and_version(self) -> None:
        self.assertEqual(self.bundle["format"], "dontlie-scitt-bundle")
        self.assertEqual(self.bundle["version"], 1)

    def test_bundle_envelopes_verify(self) -> None:
        for env_obj, receipt in zip(self.bundle["envelopes"], self.receipts):
            pem = self.bundle["public_keys"][receipt.key_id]
            result = scitt.verify_envelope_signature(env_obj, pem)
            self.assertTrue(
                result.valid,
                f"bundle envelope for receipt {receipt.id} failed: {result.reason}",
            )
            self.assertEqual(result.payload_sha256, receipt.payload_sha256)

    def test_bundle_receipts_match_envelope_order(self) -> None:
        # The bundle must keep envelope[i] aligned with receipt[i] so
        # downstream consumers can join the two arrays positionally.
        for env_obj, receipt in zip(self.bundle["envelopes"], self.receipts):
            self.assertEqual(
                int(env_obj["unprotected"][str(scitt.LABEL_RECEIPT_ID)]),
                receipt.id,
            )


class ScittTamperTest(unittest.TestCase):
    """Test 4: tampering with the payload invalidates the signature."""

    def setUp(self) -> None:
        self.root, self._temp = _isolated_workspace()
        self.receipt = storage.append("gpt-4o-mini", "p1", "r1")
        self.envelope = scitt.envelope_for_receipt(self.receipt)
        self.obj = scitt.envelope_to_json(self.envelope)
        conn = storage._connect()
        try:
            keys, _ = storage._key_material(conn)
        finally:
            conn.close()
        self.public_key_pem = keys[self.receipt.key_id]

    def tearDown(self) -> None:
        self._temp.restore()
        self._temp.cleanup()

    def test_modifying_one_payload_byte_invalidates(self) -> None:
        bad = copy.deepcopy(self.obj)
        payload = bytearray(scitt._b64u_decode(bad["payload"]))
        payload[0] ^= 0x01  # flip the lowest bit of the first byte
        bad["payload"] = scitt._b64u_encode(bytes(payload))
        result = scitt.verify_envelope_signature(bad, self.public_key_pem)
        self.assertFalse(result.valid)
        self.assertIn("does not verify", result.reason)

    def test_modifying_one_signature_byte_invalidates(self) -> None:
        bad = copy.deepcopy(self.obj)
        sig = bytearray(scitt._b64u_decode(bad["signature"]))
        sig[10] ^= 0x80
        bad["signature"] = scitt._b64u_encode(bytes(sig))
        result = scitt.verify_envelope_signature(bad, self.public_key_pem)
        self.assertFalse(result.valid)
        self.assertIn("does not verify", result.reason)

    def test_changing_unprotected_kid_does_not_break_signature(self) -> None:
        # Per COSE: the unprotected header is NOT included in Sig_structure.
        # So changing the kid alone must not affect signature verification.
        # This is the well-known COSE property that distinguishes protected
        # from unprotected header semantics.
        bad = copy.deepcopy(self.obj)
        bad["unprotected"][str(scitt.LABEL_KID)] = "deadbeef"
        result = scitt.verify_envelope_signature(bad, self.public_key_pem)
        self.assertTrue(
            result.valid,
            "unprotected header changes must not break signature verification",
        )


class ScittV2AndV3ReceiptTest(unittest.TestCase):
    """Test 5: both legacy v2 and v3 receipts produce valid envelopes."""

    def setUp(self) -> None:
        self.root, self._temp = _isolated_workspace()
        conn = storage._connect()
        try:
            _keys, _ = storage._key_material(conn)
        finally:
            conn.close()
        # We need the public key for the current key, which was generated
        # inside _isolated_workspace.
        from cryptography.hazmat.primitives import serialization
        with open(signing.PUBLIC_FILE, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        self.public_key_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
        self.public_keys = {signing.load().key_id: self.public_key_pem}

    def tearDown(self) -> None:
        self._temp.restore()
        self._temp.cleanup()

    def test_v3_receipt_envelope_carries_chain_version_3(self) -> None:
        # storage.append in this codebase always produces v3 (chain_version=3
        # in extra) because the CWD is post-v3. We confirm that property.
        r = storage.append("gpt-4o-mini", "v3 prompt", "v3 response")
        env = scitt.envelope_for_receipt(r)
        self.assertEqual(
            env.unprotected[scitt.LABEL_CHAIN_VERSION], 3,
            "current storage.append must produce v3 receipts",
        )
        result = scitt.verify_envelope_signature(env, self.public_key_pem)
        self.assertTrue(result.valid, result.reason)

    def test_legacy_v2_receipt_envelope_carries_chain_version_2(self) -> None:
        # Simulate a legacy v2 receipt by clearing the chain_version key from
        # the extra dict. The Receipt dataclass doesn't enforce chain version,
        # so we can build a v2-shaped receipt in memory and pass it to the
        # envelope builder directly.
        r_v3 = storage.append("gpt-4o-mini", "v2 prompt", "v2 response")
        # Build a v2 sibling in memory: same key/payload/sig, but extra
        # has no chain_version.
        r_v2 = copy.deepcopy(r_v3)
        r_v2.extra = {}  # v2 had no CHAIN_VERSION_KEY
        r_v2.operator_id = None  # v2 didn't have Article 12(3) fields
        env = scitt.envelope_for_receipt(r_v2)
        self.assertEqual(env.unprotected[scitt.LABEL_CHAIN_VERSION], 2)
        # No operator_key_id label in unprotected for v2.
        self.assertNotIn(scitt.LABEL_OPERATOR_KEY_ID, env.unprotected)
        result = scitt.verify_envelope_signature(env, self.public_key_pem)
        self.assertTrue(result.valid, result.reason)

    def test_v3_receipt_envelope_carries_operator_key_id(self) -> None:
        # v3 receipts (the default in this codebase) carry the operator id
        # through to the unprotected header so SCITT verifiers can attribute
        # the signed statement to an Article 12(3) operator.
        os.environ["DONTLIE_OPERATOR_ID"] = "test-operator-acme"
        try:
            r = storage.append(
                "gpt-4o-mini", "operator prompt", "operator response"
            )
        finally:
            os.environ.pop("DONTLIE_OPERATOR_ID", None)
        self.assertEqual(r.operator_id, "test-operator-acme")
        env = scitt.envelope_for_receipt(r)
        self.assertEqual(
            env.unprotected.get(scitt.LABEL_OPERATOR_KEY_ID),
            "test-operator-acme",
        )


class ScittCborRoundTripTest(unittest.TestCase):
    """Round-trip test for the CBOR encoder/decoder: every COSE_Sign1 we
    emit must decode back to the same logical structure."""

    def setUp(self) -> None:
        self.root, self._temp = _isolated_workspace()
        self.receipt = storage.append("gpt-4o-mini", "p1", "r1")
        self.envelope = scitt.envelope_for_receipt(self.receipt)

    def tearDown(self) -> None:
        self._temp.restore()
        self._temp.cleanup()

    def test_cbor_array_round_trips(self) -> None:
        cbor = scitt.emit_envelope_cbor(self.envelope)
        parsed = scitt.cbor_decode(cbor)
        # Element 0: protected bstr (encodes the protected CBOR map)
        # Element 1: unprotected CBOR map (decoded as dict)
        # Element 2: payload bstr (the 32-byte sha256)
        # Element 3: signature bstr (64 bytes)
        protected_bstr, unprotected, payload_bstr, sig_bstr = parsed
        self.assertIsInstance(protected_bstr, bytes)
        self.assertIsInstance(unprotected, dict)
        self.assertIsInstance(payload_bstr, bytes)
        self.assertIsInstance(sig_bstr, bytes)
        self.assertEqual(len(payload_bstr), 32)
        self.assertEqual(len(sig_bstr), 64)
        # The unprotected map should have all the Don't-Lie labels.
        self.assertIn(scitt.LABEL_KID, unprotected)
        self.assertIn(scitt.LABEL_CHAIN_VERSION, unprotected)
        self.assertIn(scitt.LABEL_RECEIPT_ID, unprotected)
        # The protected header should round-trip to the same logical map.
        protected_map = scitt.cbor_decode(protected_bstr)
        self.assertEqual(protected_map[1], -8)
        self.assertEqual(protected_map[3], scitt.CONTENT_TYPE_RECEIPT_HASH)


if __name__ == "__main__":
    unittest.main()
