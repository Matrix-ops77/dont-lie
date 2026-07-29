"""Focused tests for the local public reputation graph."""

from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from contextlib import closing, redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from dontlie.reputation import (
    Attestation,
    AttestationError,
    ReputationStore,
    build_attestation,
    build_revocation,
    check,
)
from dontlie.reputation.cli import main

NOW = datetime(2026, 7, 24, 12, 0, tzinfo=timezone.utc)
TIP = "ab" * 32


class ReputationFormatTest(unittest.TestCase):
    def setUp(self) -> None:
        self.key = Ed25519PrivateKey.generate()

    def build(self) -> Attestation:
        return build_attestation(
            receipt_id=7,
            chain_tip_hash=TIP,
            private_key=self.key,
            witness_count=2,
            issued_at=NOW,
            last_corroboration=NOW - timedelta(minutes=3),
        )

    def test_payload_is_exactly_five_anonymized_fields(self) -> None:
        attestation = self.build()
        self.assertEqual(
            set(attestation.payload),
            {
                "receipt_id",
                "chain_tip_hash",
                "public_key",
                "witness_count",
                "truncated_promise",
            },
        )
        serialized = attestation.to_bytes().decode("utf-8")
        self.assertNotIn("prompt", serialized)
        self.assertNotIn("response", serialized)
        self.assertNotIn("model", serialized)

    def test_round_trip_verifies_offline(self) -> None:
        original = self.build()
        decoded = Attestation.from_bytes(original.to_bytes())
        self.assertEqual(decoded.address, original.address)
        self.assertEqual(decoded.link, original.link)
        self.assertEqual(decoded.last_corroboration, NOW - timedelta(minutes=3))

    def test_payload_tampering_breaks_signature(self) -> None:
        attestation = self.build()
        envelope = json.loads(attestation.to_bytes())
        envelope["payload"]["witness_count"] = 200
        with self.assertRaisesRegex(AttestationError, "commitment"):
            Attestation.from_bytes(
                json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()
            )

    def test_unknown_extra_field_is_rejected(self) -> None:
        attestation = self.build()
        payload = dict(attestation.payload)
        payload["provider"] = "secret"
        malformed = Attestation(payload=payload, signature=attestation.signature)
        with self.assertRaisesRegex(AttestationError, "exactly five"):
            malformed.verify(now=NOW)

    def test_witness_time_invariants_are_enforced(self) -> None:
        with self.assertRaisesRegex(AttestationError, "corroboration time"):
            build_attestation(
                receipt_id=1,
                chain_tip_hash=TIP,
                private_key=self.key,
                witness_count=1,
                issued_at=NOW,
            )


class ReputationStoreTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = ReputationStore(self.root / "store")
        self.key = Ed25519PrivateKey.generate()
        self.attestation = build_attestation(
            receipt_id=5,
            chain_tip_hash=TIP,
            private_key=self.key,
            issued_at=NOW,
        )
        self.path = self.store.put(self.attestation)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_resolves_link_hash_and_portable_file(self) -> None:
        for reference in (
            self.attestation.link,
            self.attestation.address,
            str(self.path),
        ):
            self.assertEqual(
                self.store.resolve(reference).address,
                self.attestation.address,
            )

    def test_check_reports_self_unknown_and_pinned(self) -> None:
        own = check(
            self.attestation,
            store=self.store,
            self_public_key=self.key.public_key(),
            now=NOW + timedelta(hours=2),
        )
        self.assertEqual(own.signer_trust, "self")
        self.assertEqual(own.age_seconds, 7200)
        unknown = check(self.attestation, store=self.store, now=NOW)
        self.assertEqual(unknown.signer_trust, "unknown")
        pinned = check(
            self.attestation,
            store=self.store,
            trusted_fingerprints=frozenset({self.attestation.signer_fingerprint}),
            now=NOW,
        )
        self.assertEqual(pinned.signer_trust, "pinned")

    def test_owner_can_revoke_and_check_detects_it(self) -> None:
        revocation = build_revocation(
            self.attestation,
            self.key,
            revoked_at=NOW + timedelta(hours=1),
        )
        self.store.put_revocation(revocation, self.attestation)
        result = check(
            self.attestation,
            store=self.store,
            now=NOW + timedelta(hours=2),
        )
        self.assertTrue(result.revoked)
        self.assertEqual(result.revocation, revocation)

    def test_foreign_key_cannot_revoke(self) -> None:
        with self.assertRaisesRegex(AttestationError, "does not own"):
            build_revocation(self.attestation, Ed25519PrivateKey.generate())

    def test_tampered_content_address_is_rejected(self) -> None:
        fake_path = self.store.attestations / ("f" * 64 + ".json")
        fake_path.write_bytes(self.attestation.to_bytes())
        with self.assertRaisesRegex(AttestationError, "content hash mismatch"):
            self.store.resolve("f" * 64)


class ReputationCliTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.store = self.root / "store"
        self.db = self.root / "vault.db"
        self.key_path = self.root / "dontlie.key"
        key = Ed25519PrivateKey.generate()
        self.key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
        with closing(sqlite3.connect(self.db)) as connection:
            connection.execute(
                "CREATE TABLE receipts (id INTEGER PRIMARY KEY, payload_sha256 TEXT)"
            )
            connection.executemany(
                "INSERT INTO receipts VALUES (?, ?)",
                [(1, "11" * 32), (2, TIP)],
            )
            connection.commit()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_cli(self, *args: str) -> tuple[int, str, str]:
        stdout = StringIO()
        stderr = StringIO()
        common = ["--store", str(self.store), "--key", str(self.key_path)]
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main([*common, *args])
        return code, stdout.getvalue(), stderr.getvalue()

    def test_publish_link_check_and_revoke_flow(self) -> None:
        code, output, error = self.run_cli(
            "publish", "1", "--db", str(self.db)
        )
        self.assertEqual((code, error), (0, ""))
        link = next(
            line.split(":", 1)[1].strip()
            for line in output.splitlines()
            if line.startswith("link:")
        )

        code, output, error = self.run_cli("link", link)
        self.assertEqual((code, output.strip(), error), (0, link, ""))
        code, output, error = self.run_cli("check", link)
        self.assertEqual((code, error), (0, ""))
        self.assertIn("trust state:         ACTIVE", output)
        self.assertIn("signer trust:        self", output)
        self.assertIn("witness count:       0", output)
        self.assertIn("last corroboration: none", output)

        code, _, error = self.run_cli("revoke", link)
        self.assertEqual((code, error), (0, ""))
        code, output, error = self.run_cli("check", link)
        self.assertEqual((code, error), (2, ""))
        self.assertIn("trust state:         REVOKED", output)

    def test_publish_rejects_missing_receipt(self) -> None:
        code, _, error = self.run_cli(
            "publish", "99", "--db", str(self.db)
        )
        self.assertEqual(code, 1)
        self.assertIn("receipt 99 not found", error)


if __name__ == "__main__":
    unittest.main()
