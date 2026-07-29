"""Tests for RedactionPolicy wiring into storage.append."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-redaction-wiring-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"
os.environ["DONTLIE_REDACTION_POLICY"] = "default"

from dontlie import storage


class RedactionWiringTest(unittest.TestCase):
    def setUp(self) -> None:
        with storage.db() as conn:
            conn.executescript(storage.SCHEMA)
            conn.execute("DELETE FROM receipts")
            conn.execute("DELETE FROM key_history")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
        signing = __import__("dontlie.sign", fromlist=["generate"])
        signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
        for path in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
            path.unlink(missing_ok=True)
        signing.generate()

    def test_secret_in_prompt_is_redacted_before_signing(self) -> None:
        receipt = storage.append(
            model="mock-1",
            prompt="my key is sk-abcdef1234567890abcdef1234567890AB",
            response="ok",
        )
        self.assertNotIn("sk-abcdef1234567890abcdef1234567890AB", receipt.prompt)
        self.assertIn("[REDACTED:OPENAI_API_KEY]", receipt.prompt)
        self.assertTrue(receipt.extra["redaction"]["redacted"])
        self.assertIn("OPENAI_API_KEY", receipt.extra["redaction"]["rules"])

    def test_redaction_off_keeps_raw_values(self) -> None:
        prev = os.environ.get("DONTLIE_REDACTION_POLICY")
        os.environ["DONTLIE_REDACTION_POLICY"] = "off"
        try:
            receipt = storage.append(
                model="mock-1",
                prompt="my key is sk-abcdef1234567890abcdef1234567890AB",
                response="ok",
            )
            self.assertIn("sk-abcdef1234567890abcdef1234567890AB", receipt.prompt)
        finally:
            if prev is None:
                os.environ.pop("DONTLIE_REDACTION_POLICY", None)
            else:
                os.environ["DONTLIE_REDACTION_POLICY"] = prev

    def test_redacted_receipt_verifies_cleanly(self) -> None:
        storage.append(
            model="mock-1",
            prompt="ping wayne@example.com",
            response="pong",
        )
        report = storage.verify_chain_report()
        self.assertTrue(report.valid)
        self.assertEqual(report.ok_count, 1)
        self.assertEqual(report.bad_count, 0)


if __name__ == "__main__":
    unittest.main()
