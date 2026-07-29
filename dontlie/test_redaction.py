import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-redaction-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

from dontlie import redaction, storage
from dontlie import sign as signing

SUPPORTED_RULES = (
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "EMAIL",
    "SSN",
    "CREDIT_CARD",
    "PHONE",
    "JWT",
)


def fresh_state(name: str) -> None:
    signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
    for path in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
        path.unlink(missing_ok=True)
    signing.generate()
    storage.DB_PATH = Path(_TMP) / name
    with sqlite3.connect(storage.DB_PATH) as conn:
        conn.executescript(storage.SCHEMA)
        conn.execute("DELETE FROM receipts")
        conn.execute("DELETE FROM key_history")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")


class RedactionApiSurfaceTest(unittest.TestCase):
    def test_redaction_policy_class_exported(self) -> None:
        self.assertTrue(callable(redaction.RedactionPolicy))

    def test_default_policy_includes_required_rules(self) -> None:
        policy = redaction.RedactionPolicy()
        text = (
            "Email user@example.com key sk-abcdefghijklmnopqrstuvwxyz123456 "
            "anthropic sk-ant-abcdefghijklmnopqrstuvwxyz123456789012 "
            "ssn 123-45-6789 card 4111111111111111 phone 415-555-0123 "
            "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.sigpartabcdefghijklmnop"
        )
        report = policy.apply(text)
        rules = {d.rule for d in report.detections}
        for rule in SUPPORTED_RULES:
            self.assertIn(rule, rules, msg=f"missing {rule} in {rules}")
        self.assertNotIn("user@example.com", report.text)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", report.text)
        self.assertNotIn("sk-ant-abcdefghijklmnopqrstuvwxyz123456789012", report.text)
        self.assertNotIn("123-45-6789", report.text)
        self.assertNotIn("4111111111111111", report.text)
        self.assertNotIn("415-555-0123", report.text)

    def test_disabled_rule_skips(self) -> None:
        policy = redaction.RedactionPolicy(
            rules=[r for r in SUPPORTED_RULES if r != "EMAIL"]
        )
        text = "Email user@example.com about the upgrade"
        report = policy.apply(text)
        self.assertIn("user@example.com", report.text)
        self.assertFalse(any(d.rule == "EMAIL" for d in report.detections))

    def test_redaction_is_idempotent(self) -> None:
        policy = redaction.RedactionPolicy()
        text = "ping user@example.com about sk-abcdefghijklmnopqrstuvwxyz123456"
        first = policy.apply(text)
        second = policy.apply(first.text)
        self.assertEqual(second.text, first.text)
        self.assertEqual(second.detections, [])

    def test_no_secrets_returns_unchanged(self) -> None:
        policy = redaction.RedactionPolicy()
        text = "Just a normal conversation about the project status."
        report = policy.apply(text)
        self.assertEqual(report.text, text)
        self.assertFalse(report.detections)
        self.assertFalse(report.redacted)
        self.assertEqual(report.to_extra(), {"redacted": False, "rules": [], "count": 0})

    def test_report_to_extra_serializes(self) -> None:
        policy = redaction.RedactionPolicy()
        report = policy.apply("Contact user@example.com please")
        extra = report.to_extra()
        self.assertTrue(extra["redacted"])
        self.assertEqual(extra["rules"], ["EMAIL"])
        self.assertEqual(extra["count"], 1)


class RedactionKindCoverageTest(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = redaction.RedactionPolicy()

    def test_anthropic_key(self) -> None:
        text = "Authorization: sk-ant-abcdefghijklmnopqrstuvwxyz123456789012"
        report = self.policy.apply(text)
        self.assertNotIn("sk-ant-abcdefghijklmnopqrstuvwxyz123456789012", report.text)
        self.assertTrue(any(d.rule == "ANTHROPIC_API_KEY" for d in report.detections))

    def test_openai_key(self) -> None:
        text = "Use key sk-abcdefghijklmnopqrstuvwxyz123456 please"
        report = self.policy.apply(text)
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz123456", report.text)
        self.assertTrue(any(d.rule == "OPENAI_API_KEY" for d in report.detections))

    def test_email(self) -> None:
        report = self.policy.apply("ping user@example.com about the upgrade")
        self.assertNotIn("user@example.com", report.text)
        self.assertTrue(any(d.rule == "EMAIL" for d in report.detections))

    def test_ssn(self) -> None:
        report = self.policy.apply("Patient SSN 123-45-6789 was processed")
        self.assertNotIn("123-45-6789", report.text)
        self.assertTrue(any(d.rule == "SSN" for d in report.detections))

    def test_credit_card_valid_luhn(self) -> None:
        report = self.policy.apply("Charge 4111111111111111 today")
        self.assertNotIn("4111111111111111", report.text)
        self.assertTrue(any(d.rule == "CREDIT_CARD" for d in report.detections))

    def test_phone(self) -> None:
        report = self.policy.apply("Call 415-555-0123 anytime")
        self.assertNotIn("415-555-0123", report.text)
        self.assertTrue(any(d.rule == "PHONE" for d in report.detections))

    def test_jwt(self) -> None:
        token = (
            "eyJhbGciOiJIUzI1NiJ9."
            "eyJzdWIiOiJ1c2VyIn0."
            "sigpartabcdefghijklmnop"
        )
        report = self.policy.apply(f"Bearer {token}")
        self.assertNotIn(token, report.text)
        self.assertTrue(any(d.rule == "JWT" for d in report.detections))


class ReceiptPersistenceRedactionTest(unittest.TestCase):
    def setUp(self) -> None:
        fresh_state(f"vault-{id(self)}.db")
        self.policy = redaction.RedactionPolicy()

    def test_redacted_receipt_does_not_contain_secret(self) -> None:
        secret_email = "user@example.com"
        secret_key = "sk-abcdefghijklmnopqrstuvwxyz123456"
        prompt = f"Send status update to {secret_email} using key {secret_key}"
        response = f"Email sent to {secret_email} from operator"
        prompt_report = self.policy.apply(prompt)
        response_report = self.policy.apply(response)
        receipt = storage.append(
            model="gpt-4o-mini",
            prompt=prompt_report.text,
            response=response_report.text,
        )
        self.assertNotIn(secret_email, receipt.prompt)
        self.assertNotIn(secret_email, receipt.response)
        self.assertNotIn(secret_key, receipt.prompt)
        self.assertNotIn(secret_key, receipt.response)
        ok, bad = storage.verify_chain()
        self.assertEqual(bad, 0)
        self.assertEqual(ok, 1)

    def test_redaction_metadata_in_extra(self) -> None:
        policy_report = self.policy.apply("Email user@example.com about sk-abcdefghijklmnopqrstuvwxyz123456")
        receipt = storage.append(
            model="gpt-4o-mini",
            prompt=policy_report.text,
            response="OK",
            extra={"redaction": policy_report.to_extra()},
        )
        self.assertTrue(receipt.extra["redaction"]["redacted"])
        self.assertIn("EMAIL", receipt.extra["redaction"]["rules"])
        self.assertIn("OPENAI_API_KEY", receipt.extra["redaction"]["rules"])
        self.assertGreaterEqual(receipt.extra["redaction"]["count"], 2)


if __name__ == "__main__":
    unittest.main()
