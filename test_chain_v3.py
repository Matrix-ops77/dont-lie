"""Tests for the v3 chain (operator_id, deployer_id, system_id).

v3 receipts (chain version >= 3) include three Article 12(3)-mandated
identity fields in the signed canonical payload. v2 receipts continue
to verify using the legacy 9-field encoding.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path


class ChainV3Test(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory(prefix="dontlie-v3-")
        root = Path(self._temp.name)
        self._orig_env = {
            "DONTLIE_KEY_DIR": os.environ.get("DONTLIE_KEY_DIR"),
            "DONTLIE_DB": os.environ.get("DONTLIE_DB"),
            "DONTLIE_NO_WAL": os.environ.get("DONTLIE_NO_WAL"),
            "DONTLIE_OPERATOR_ID": os.environ.get("DONTLIE_OPERATOR_ID"),
            "DONTLIE_DEPLOYER_ID": os.environ.get("DONTLIE_DEPLOYER_ID"),
            "DONTLIE_SYSTEM_ID": os.environ.get("DONTLIE_SYSTEM_ID"),
        }
        os.environ["DONTLIE_KEY_DIR"] = str(root / "keys")
        os.environ["DONTLIE_DB"] = str(root / "vault.db")
        os.environ["DONTLIE_NO_WAL"] = "1"
        os.environ["DONTLIE_OPERATOR_ID"] = "ops-team-acme"
        os.environ["DONTLIE_DEPLOYER_ID"] = "deployer-prod-east"
        os.environ["DONTLIE_SYSTEM_ID"] = "agent-billing-2026-q3"
        from dontlie import sign as signing
        from dontlie import storage
        self.signing = signing
        self.storage = storage
        signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
        for p in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
            if p.exists():
                p.unlink()
        signing.generate()
        storage.init()
        conn = storage._connect()
        try:
            conn.execute("DELETE FROM receipts")
            conn.execute("DELETE FROM key_history")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
            conn.commit()
        finally:
            conn.close()

    def tearDown(self):
        for k, v in self._orig_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        self._temp.cleanup()

    def test_v3_receipt_includes_identity_fields(self):
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        self.assertEqual(r.extra.get("_dontlie_chain_version"), 3)
        self.assertEqual(r.operator_id, "ops-team-acme")
        self.assertEqual(r.deployer_id, "deployer-prod-east")
        self.assertEqual(r.system_id, "agent-billing-2026-q3")

    def test_v3_canonical_payload_includes_identity_fields(self):
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        payload = self.storage._canonical_payload(r).decode("utf-8")
        self.assertIn('"deployer_id":"deployer-prod-east"', payload)
        self.assertIn('"operator_id":"ops-team-acme"', payload)
        self.assertIn('"system_id":"agent-billing-2026-q3"', payload)

    def test_v3_receipt_verifies(self):
        self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 1)
        self.assertEqual(bad, 0)

    def test_tamper_operator_id_breaks_verification(self):
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        conn = self.storage._connect()
        try:
            conn.execute(
                "UPDATE receipts SET operator_id = 'hacked' WHERE id = ?", (r.id,)
            )
            conn.commit()
        finally:
            conn.close()
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 0)
        self.assertEqual(bad, 1)

    def test_tamper_deployer_id_breaks_verification(self):
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        conn = self.storage._connect()
        try:
            conn.execute(
                "UPDATE receipts SET deployer_id = 'hacked' WHERE id = ?", (r.id,)
            )
            conn.commit()
        finally:
            conn.close()
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 0)
        self.assertEqual(bad, 1)

    def test_tamper_system_id_breaks_verification(self):
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        conn = self.storage._connect()
        try:
            conn.execute(
                "UPDATE receipts SET system_id = 'hacked' WHERE id = ?", (r.id,)
            )
            conn.commit()
        finally:
            conn.close()
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 0)
        self.assertEqual(bad, 1)

    def test_v2_receipts_grandfathered_unchanged(self):
        """A pre-existing v2 receipt (signed with the 9-field payload) MUST
        keep verifying after the v3 schema migration.
        """
        # 1. Append a v3 receipt
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        # 2. Re-sign it with the v2 canonical payload to simulate a v2 receipt
        cap = self.storage._canonical_payload
        kp = self.signing.load()
        v2_receipt = copy.deepcopy(r)
        v2_receipt.operator_id = None
        v2_receipt.deployer_id = None
        v2_receipt.system_id = None
        v2_receipt.extra = {k: v for k, v in (r.extra or {}).items()
                            if k != "_dontlie_chain_version"}
        v2_payload = cap(v2_receipt)
        v2_hash = hashlib.sha256(v2_payload).hexdigest()
        v2_sig = self.signing.sign_bytes(kp, v2_payload)
        # 3. Write the v2-shaped row directly
        conn = self.storage._connect()
        try:
            conn.execute(
                "UPDATE receipts SET operator_id = NULL, deployer_id = NULL, "
                "system_id = NULL, extra = ?, payload_sha256 = ?, signature = ? "
                "WHERE id = ?",
                (json.dumps(v2_receipt.extra), v2_hash, v2_sig, r.id),
            )
            conn.commit()
        finally:
            conn.close()
        r2 = self.storage.get_receipt(r.id)
        self.assertIsNone(r2.extra.get("_dontlie_chain_version"))
        self.assertIsNone(r2.operator_id)
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 1)
        self.assertEqual(bad, 0)
        # The canonical payload should NOT include the identity fields
        payload = self.storage._canonical_payload(r2).decode("utf-8")
        self.assertNotIn("operator_id", payload)
        self.assertNotIn("deployer_id", payload)
        self.assertNotIn("system_id", payload)

    def test_v3_signature_does_not_verify_against_v2_payload(self):
        """A v3 receipt signed with the 12-field payload must NOT verify if
        the 9-field payload is used. This is the regression test that
        confirms the v3 fields are actually being signed.
        """
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        cap = self.storage._canonical_payload
        original = r.extra.get("_dontlie_chain_version")
        r.extra["_dontlie_chain_version"] = 2
        r.operator_id = None
        r.deployer_id = None
        r.system_id = None
        wrong_payload = cap(r)
        wrong_hash = hashlib.sha256(wrong_payload).hexdigest()
        self.assertNotEqual(wrong_hash, r.payload_sha256)
        r.extra["_dontlie_chain_version"] = original

    def test_v3_receipt_canonical_encoding_is_stable(self):
        """The canonical payload must be deterministic for the same receipt
        (so external verifiers can re-derive the hash byte-for-byte).
        """
        r = self.storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        p1 = self.storage._canonical_payload(r)
        p2 = self.storage._canonical_payload(r)
        self.assertEqual(p1, p2)
        self.assertEqual(hashlib.sha256(p1).hexdigest(), r.payload_sha256)


if __name__ == "__main__":
    unittest.main(verbosity=2)
