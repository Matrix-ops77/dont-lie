"""Tests for the redaction policy."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-redaction-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

from dontlie.redaction import RedactionPolicy


class RedactionPolicyTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = RedactionPolicy()

    def test_openai_key_replaced(self) -> None:
        text = "use key sk-abcdef1234567890abcdef1234567890AB here"
        report = self.policy.apply(text)
        self.assertTrue(report.redacted)
        self.assertNotIn("sk-abcdef1234567890abcdef1234567890AB", report.text)
        self.assertIn("[REDACTED:OPENAI_API_KEY]", report.text)

    def test_anthropic_key_replaced(self) -> None:
        text = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz1234567890"
        report = self.policy.apply(text)
        self.assertTrue(report.redacted)
        self.assertIn("[REDACTED:ANTHROPIC_API_KEY]", report.text)

    def test_email_replaced(self) -> None:
        text = "ping wayne@example.com about this"
        report = self.policy.apply(text)
        self.assertTrue(report.redacted)
        self.assertIn("[REDACTED:EMAIL]", report.text)

    def test_ssn_replaced(self) -> None:
        text = "user SSN 123-45-6789 must be protected"
        report = self.policy.apply(text)
        self.assertTrue(report.redacted)
        self.assertIn("[REDACTED:SSN]", report.text)

    def test_credit_card_luhn_only(self) -> None:
        text_with_real = "card 4111 1111 1111 1111 ok"
        text_with_fake = "this is not a card 1234 5678 9012 3456"
        # 4111 1111 1111 1111 passes Luhn; 1234 5678 9012 3456 does not.
        self.assertTrue(self.policy.apply(text_with_real).redacted)
        # The fake card should not match.
        self.assertFalse(self.policy.apply(text_with_fake).redacted)

    def test_overlapping_email_wins_shortest(self) -> None:
        text = "x@y.com and sk-abcdefghijklmnopqrstuvwxyz1234567"
        report = self.policy.apply(text)
        rules = {d.rule for d in report.detections}
        self.assertIn("EMAIL", rules)
        self.assertIn("OPENAI_API_KEY", rules)

    def test_clean_text_unchanged(self) -> None:
        text = "this is a clean conversation about model behavior"
        report = self.policy.apply(text)
        self.assertFalse(report.redacted)
        self.assertEqual(report.text, text)

    def test_private_key_block_redacted(self) -> None:
        block = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAabcdefghijklmnopqrstuvwxyz1234567890ABCDEFG\n"
            "-----END RSA PRIVATE KEY-----"
        )
        report = self.policy.apply(block)
        self.assertTrue(report.redacted)
        self.assertIn("[REDACTED:PRIVATE_KEY_BLOCK]", report.text)

    def test_redaction_report_to_extra_metadata(self) -> None:
        text = "stripe key: sk_live_abcdefghijklmnop1234567890"
        report = self.policy.apply(text)
        meta = report.to_extra()
        self.assertTrue(meta["redacted"])
        self.assertIn("STRIPE_API_KEY", meta["rules"])


if __name__ == "__main__":
    unittest.main()
