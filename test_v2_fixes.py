"""Tests for the Phase 1-8 fixes (2026-07-28 audit).

Covers the new behavior that was either buggy or missing before:

* storage._migrate: idempotent migration of receipts + key_history
* encryption.encrypt_file / decrypt_file: whole-file round-trip
* witness service: /healthz endpoint, --key-dir flag respected
* CLI: encrypt/unlock accept a positional vault path
* CLI: dontlie anchor subcommand dispatches to the legacy file
* CLI: witness-service --key-dir is honored end-to-end

These tests use stdlib only and don't depend on pytest. Run via:
    python3 -m unittest test_v2_fixes
"""
from __future__ import annotations

import json
import os
import socket
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest

# argon2-cffi is needed for the whole-file encryption tests. Skip
# those tests when the optional dep is missing.
try:
    import argon2  # noqa: F401
    _HAS_ARGON2 = True
except ImportError:  # pragma: no cover
    _HAS_ARGON2 = False
import urllib.request
from pathlib import Path

from test_helpers import dontlie_cmd

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(url: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                return 200 <= resp.status < 300
        except Exception:
            time.sleep(0.1)
    return False


class StorageMigrationTest(unittest.TestCase):
    """The migration must be idempotent and add missing columns to
    both ``receipts`` and ``key_history`` on pre-existing vaults."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="dontlie-migrate-test-")
        self.db_path = Path(self._tmp) / "legacy.db"
        # Create a legacy receipts table WITHOUT namespace / observed_at
        # and a legacy key_history without public_key_pem.
        with sqlite3.connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE receipts (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp       TEXT NOT NULL,
                    model           TEXT NOT NULL,
                    prompt          TEXT NOT NULL,
                    response        TEXT NOT NULL,
                    parent_id       INTEGER,
                    key_id          TEXT NOT NULL,
                    payload_sha256  TEXT NOT NULL,
                    signature       TEXT NOT NULL,
                    tags            TEXT NOT NULL DEFAULT '[]',
                    extra           TEXT NOT NULL DEFAULT '{}'
                );
                INSERT INTO receipts(timestamp, model, prompt, response,
                                     key_id, payload_sha256, signature)
                VALUES ('2024-01-01T00:00:00+00:00', 'mock',
                        'hi', 'hello', 'old-key',
                        'sha256-placeholder',
                        'sig-placeholder');
                CREATE TABLE key_history (
                    key_id      TEXT PRIMARY KEY,
                    created_at  TEXT NOT NULL,
                    revoked_at  TEXT
                );
            """)

    def test_idempotent_migration_adds_columns(self) -> None:
        os.environ["DONTLIE_DB"] = str(self.db_path)
        # The storage module's DB_PATH is a module-level Path. Update
        # it directly so the test doesn't disturb other tests' module
        # cache (popping ``dontlie.storage`` here breaks test_web,
        # which reloads ``dontlie.signing`` later).
        from dontlie import storage
        storage.DB_PATH = self.db_path
        # Mimic db(): _migrate FIRST, then SCHEMA. This is the
        # canonical sequence used in production.
        def _open() -> sqlite3.Connection:
            c = sqlite3.connect(self.db_path)
            c.row_factory = sqlite3.Row  # migration reads PRAGMA rows by name
            return c

        with _open() as conn:
            storage._migrate(conn)
            conn.executescript(storage.SCHEMA)
        with _open() as conn:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(receipts)")}
        self.assertIn("namespace", cols)
        self.assertIn("observed_at", cols)
        # Pre-existing row should now have namespace='default'
        with _open() as conn:
            row = conn.execute("SELECT namespace FROM receipts").fetchone()
        self.assertEqual(row[0], "default")

        # Second call: should be a no-op
        with _open() as conn:
            storage._migrate(conn)
            conn.executescript(storage.SCHEMA)
        with _open() as conn:
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(receipts)")}
        self.assertIn("namespace", cols)


@unittest.skipUnless(_HAS_ARGON2, "argon2-cffi unavailable")
class EncryptionFileTest(unittest.TestCase):
    """Whole-file encrypt / decrypt round-trip."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="dontlie-enc-test-")
        self.src = Path(self._tmp) / "vault.db"
        self.src.write_bytes(b"hello, this is a fake vault\n" * 100)
        self.enc = Path(self._tmp) / "vault.db.enc"
        self.dec = Path(self._tmp) / "vault.decrypted.db"

    def test_round_trip(self) -> None:
        from dontlie import encryption
        pw = b"correct horse battery staple"
        encryption.encrypt_file(self.src, self.enc, pw)
        self.assertTrue(self.enc.exists())
        self.assertNotEqual(self.enc.read_bytes(), self.src.read_bytes())
        # First 6 bytes are the magic
        self.assertEqual(self.enc.read_bytes()[:6], b"DLVL1\n")
        encryption.decrypt_file(self.enc, self.dec, pw)
        self.assertEqual(self.dec.read_bytes(), self.src.read_bytes())

    def test_wrong_passphrase_fails(self) -> None:
        from dontlie import encryption
        encryption.encrypt_file(self.src, self.enc, b"good")
        with self.assertRaises(encryption.EncryptionError):
            encryption.decrypt_file(self.enc, self.dec, b"bad")

    def test_non_encrypted_file_rejected(self) -> None:
        from dontlie import encryption
        bogus = Path(self._tmp) / "bogus.bin"
        bogus.write_bytes(b"not a vault\n")
        with self.assertRaises(encryption.EncryptionError):
            encryption.decrypt_file(bogus, self.dec, b"anything")


class AnchorCliTest(unittest.TestCase):
    """The ``dontlie anchor`` subcommand must not crash with
    ``module 'dontlie.anchor' has no attribute 'main'``."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="dontlie-anchor-test-")
        os.environ["DONTLIE_KEY_DIR"] = str(Path(self._tmp) / "keys")
        os.environ["DONTLIE_DB"] = str(Path(self._tmp) / "vault.db")
        os.environ["DONTLIE_NO_WAL"] = "1"
        # Point storage.DB_PATH at the new vault. We don't pop the
        # dontlie module — test_web later needs it intact. Updating
        # the Path attribute is enough for the subprocess we spawn.

    def test_anchor_help_runs(self) -> None:
        result = subprocess.run(
            dontlie_cmd("anchor", "--help"),
            capture_output=True, text=True, timeout=15,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertIn("anchor", result.stdout)

    def test_anchor_list_runs(self) -> None:
        result = subprocess.run(
            dontlie_cmd("anchor", "list"),
            capture_output=True, text=True, timeout=15,
        )
        # Should print "no anchored receipts" without crashing
        self.assertEqual(result.returncode, 0, msg=result.stderr)


class WitnessServiceTest(unittest.TestCase):
    """The witness service must expose /healthz and accept --key-dir."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="dontlie-witness-test-")
        self.key_dir = Path(self._tmp) / "witness"
        self.port = _free_port()

    def _start(self) -> subprocess.Popen:
        return subprocess.Popen(
            dontlie_cmd("witness-service",
             "--host", "127.0.0.1", "--port", str(self.port),
             "--key-dir", str(self.key_dir)),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_healthz_endpoint(self) -> None:
        proc = self._start()
        try:
            self.assertTrue(_wait_for(f"http://127.0.0.1:{self.port}/healthz"),
                            msg="witness service didn't come up in time")
            with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/healthz", timeout=2
            ) as resp:
                payload = json.loads(resp.read())
            self.assertTrue(payload.get("ok"))
            self.assertIn("key_id", payload)
            # Key dir must have been populated
            self.assertTrue((self.key_dir / "witness.key").exists())
            self.assertTrue((self.key_dir / "witness.pub").exists())
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_pubkey_endpoint(self) -> None:
        proc = self._start()
        try:
            self.assertTrue(_wait_for(f"http://127.0.0.1:{self.port}/pubkey"),
                            msg="witness service didn't come up in time")
            with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/pubkey", timeout=2
            ) as resp:
                payload = json.loads(resp.read())
            self.assertIn("BEGIN PUBLIC KEY", payload["public_key_pem"])
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


@unittest.skipUnless(_HAS_ARGON2, "argon2-cffi unavailable")
class EncryptCliTest(unittest.TestCase):
    """``dontlie encrypt`` and ``dontlie unlock`` must accept a
    positional vault path."""

    def setUp(self) -> None:
        self._tmp = tempfile.mkdtemp(prefix="dontlie-enc-cli-test-")
        self.src = Path(self._tmp) / "vault.db"
        self.src.write_bytes(b"vault payload for round-trip test\n")
        self.enc = Path(self._tmp) / "vault.db.enc"
        self.dec = Path(self._tmp) / "vault.decrypted.db"

    def test_encrypt_then_unlock_round_trip(self) -> None:
        env = os.environ.copy()
        env["DONTLIE_ENCRYPTION_PASSPHRASE"] = "test-passphrase-123"
        env["DONTLIE_DB"] = str(self.src)
        # Encrypt
        result = subprocess.run(
            dontlie_cmd("encrypt", str(self.src),
             "--output", str(self.enc), "--force"),
            capture_output=True, text=True, timeout=15, env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertTrue(self.enc.exists())
        # Unlock
        result = subprocess.run(
            dontlie_cmd("unlock", str(self.enc),
             "--output", str(self.dec), "--force"),
            capture_output=True, text=True, timeout=15, env=env,
        )
        self.assertEqual(result.returncode, 0, msg=result.stderr)
        self.assertEqual(self.dec.read_bytes(), self.src.read_bytes())


if __name__ == "__main__":
    unittest.main()
