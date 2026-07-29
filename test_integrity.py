"""Integrity, migration, and portable verification tests."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from dontlie import cli, storage
from dontlie import sign as signing


class IntegrityVerificationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.old_paths = (
            signing.KEY_DIR,
            signing.PRIVATE_FILE,
            signing.PUBLIC_FILE,
            signing.KEY_ID_FILE,
            storage.DB_PATH,
        )
        self.temp_dir = tempfile.TemporaryDirectory(prefix="dontlie-integrity-")
        root = Path(self.temp_dir.name)
        signing.KEY_DIR = root / "keys"
        signing.PRIVATE_FILE = signing.KEY_DIR / "dontlie.key"
        signing.PUBLIC_FILE = signing.KEY_DIR / "dontlie.pub"
        signing.KEY_ID_FILE = signing.KEY_DIR / "key_id"
        storage.DB_PATH = root / "vault.db"
        signing.generate()
        storage.init()

    def tearDown(self) -> None:
        (
            signing.KEY_DIR,
            signing.PRIVATE_FILE,
            signing.PUBLIC_FILE,
            signing.KEY_ID_FILE,
            storage.DB_PATH,
        ) = self.old_paths
        self.temp_dir.cleanup()

    def test_deleted_intermediate_row_breaks_continuity(self) -> None:
        for index in range(3):
            storage.append("m", f"p{index}", f"r{index}")
        with sqlite3.connect(storage.DB_PATH) as conn:
            conn.execute("PRAGMA foreign_keys = OFF")
            conn.execute("DELETE FROM receipts WHERE id = 2")

        report = storage.verify_chain_report()
        self.assertEqual((report.ok_count, report.bad_count), (1, 1))
        reasons = [issue.reason for issue in report.issues]
        self.assertTrue(
            any("missing intermediate" in reason for reason in reasons)
        )
        self.assertTrue(any("parent_id" in reason for reason in reasons))

    def test_receipts_embed_previous_payload_hash(self) -> None:
        first = storage.append("m", "p1", "r1")
        second = storage.append("m", "p2", "r2")
        self.assertEqual(
            first.extra[storage.CHAIN_VERSION_KEY], storage.CHAIN_VERSION
        )
        self.assertIsNone(first.extra[storage.PARENT_HASH_KEY])
        self.assertEqual(
            second.extra[storage.PARENT_HASH_KEY], first.payload_sha256
        )
        self.assertEqual(storage.verify_chain(), (2, 0))

    def test_spliced_valid_receipt_breaks_parent_hash_link(self) -> None:
        first = storage.append("m", "chain-a-first", "a1")
        storage.append("m", "chain-a-second", "a2")
        original_db = storage.DB_PATH

        other_db = Path(self.temp_dir.name) / "other.db"
        storage.DB_PATH = other_db
        storage.init()
        replacement = storage.append("m", "chain-b-first", "b1")
        storage.DB_PATH = original_db

        with sqlite3.connect(original_db) as conn:
            conn.execute(
                """
                UPDATE receipts
                SET timestamp=?, model=?, prompt=?, response=?, parent_id=?,
                    key_id=?, payload_sha256=?, signature=?, tags=?, extra=?
                WHERE id=1
                """,
                (
                    replacement.timestamp,
                    replacement.model,
                    replacement.prompt,
                    replacement.response,
                    replacement.parent_id,
                    replacement.key_id,
                    replacement.payload_sha256,
                    replacement.signature,
                    json.dumps(replacement.tags),
                    json.dumps(replacement.extra),
                ),
            )

        report = storage.verify_chain_report()
        self.assertFalse(report.valid)
        self.assertTrue(
            any("parent sha256" in issue.reason for issue in report.issues)
        )
        self.assertNotEqual(first.payload_sha256, replacement.payload_sha256)

    def test_reserved_chain_metadata_cannot_be_overridden(self) -> None:
        with self.assertRaisesRegex(ValueError, "reserved"):
            storage.append(
                "m",
                "p",
                "r",
                extra={storage.PARENT_HASH_KEY: "forged"},
            )

    def test_rejects_parent_that_is_not_current_head(self) -> None:
        storage.append("m", "p1", "r1")
        storage.append("m", "p2", "r2")
        with self.assertRaisesRegex(ValueError, "current chain head"):
            storage.append("m", "branch", "bad", parent_id=1)
        self.assertEqual(storage.count(), 2)
        self.assertEqual(storage.verify_chain(), (2, 0))

    def test_bundle_verifies_without_local_private_key(self) -> None:
        storage.append("m", "p1", "r1")
        storage.append("m", "p2", "r2")
        bundle = Path(self.temp_dir.name) / "receipts.bundle.json"
        self.assertEqual(storage.export_bundle(bundle), 2)

        signing.PRIVATE_FILE.unlink()
        signing.PUBLIC_FILE.unlink()
        signing.KEY_ID_FILE.unlink()
        report = storage.verify_export(bundle)
        self.assertTrue(report.valid)
        self.assertEqual((report.ok_count, report.bad_count), (2, 0))

    def test_cli_exports_and_verifies_portable_bundle(self) -> None:
        storage.append("m", "p", "r")
        bundle = Path(self.temp_dir.name) / "cli.bundle.json"
        self.assertEqual(cli.main(["export", str(bundle), "--bundle"]), 0)
        self.assertTrue(bundle.exists())
        self.assertEqual(
            cli.main(["verify", "--export", str(bundle), "--verbose"]),
            0,
        )

    def test_bundle_tampering_is_reported(self) -> None:
        storage.append("m", "p", "r")
        bundle = Path(self.temp_dir.name) / "receipts.bundle.json"
        storage.export_bundle(bundle)
        document = json.loads(bundle.read_text(encoding="utf-8"))
        document["receipts"][0]["response"] = "tampered"
        bundle.write_text(json.dumps(document), encoding="utf-8")

        report = storage.verify_export(bundle)
        self.assertFalse(report.valid)
        self.assertEqual(report.bad_count, 1)
        self.assertTrue(
            any("sha256 mismatch" in issue.reason for issue in report.issues)
        )

    def test_key_rotation_retains_each_verification_key(self) -> None:
        first = storage.append("m", "p1", "r1")
        signing.generate()
        second = storage.append("m", "p2", "r2")
        self.assertNotEqual(first.key_id, second.key_id)
        self.assertEqual(storage.verify_chain(), (2, 0))

    def test_external_key_pins_bundle_verification(self) -> None:
        receipt = storage.append("m", "p", "r")
        bundle = Path(self.temp_dir.name) / "receipts.bundle.json"
        storage.export_bundle(bundle)
        other_key = signing.generate()

        report = storage.verify_export(
            bundle,
            {
                receipt.key_id: signing.public_key_to_pem(other_key.public),
            },
        )
        self.assertFalse(report.valid)
        self.assertTrue(
            any("key id mismatch" in issue.reason for issue in report.issues)
        )

    def test_legacy_schema_is_migrated_additively(self) -> None:
        legacy = Path(self.temp_dir.name) / "legacy.db"
        with sqlite3.connect(legacy) as conn:
            conn.execute(
                """
                CREATE TABLE key_history (
                    key_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    revoked_at TEXT
                )
                """
            )
        storage.DB_PATH = legacy
        storage.init()
        with sqlite3.connect(legacy) as conn:
            columns = {
                row[1] for row in conn.execute("PRAGMA table_info(key_history)")
            }
        self.assertIn("public_key_pem", columns)

    def test_legacy_jsonl_can_be_verified_with_explicit_key(self) -> None:
        receipt = storage.append("m", "p", "r")
        exported = Path(self.temp_dir.name) / "receipts.jsonl"
        storage.export(exported)
        report = storage.verify_export(
            exported,
            {
                receipt.key_id: signing.public_key_pem(),
            },
        )
        self.assertTrue(report.valid)


if __name__ == "__main__":
    unittest.main()
