"""End-to-end integration tests for the encryption-at-rest path.

This suite stitches together the production code paths that ``dontlie
encrypt`` / ``dontlie unlock`` exercise, so we have a single artifact that
proves the full sign-encrypt-decrypt-verify cycle preserves receipt
integrity, detects tampering, and fails closed on a wrong passphrase or
corrupted ciphertext.

Test layout follows ``test_chain_v3.py``: per-test isolated vault via
``tempfile.TemporaryDirectory`` and env-var swap; original env restored in
``tearDown`` even if the test fails.

Run with::

    python3 -m unittest test_encryption_e2e
"""

from __future__ import annotations

import importlib
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

# NOTE: ``storage`` and ``signing`` are imported inside ``EncryptionE2EBase.setUp``
# because they read ``DONTLIE_DB`` / ``DONTLIE_KEY_DIR`` at *module load* time.
# An import at the top of this file would bind ``DB_PATH`` against the
# developer's real env and the per-test env swap would silently have no effect.
from dontlie import encryption

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _argon2_available() -> bool:
    try:
        import argon2.low_level  # noqa: F401
        return True
    except Exception:
        return False


def _flip_byte_in_middle(path: Path) -> int:
    """Flip one bit in the middle of ``path`` and return the offset touched.

    Used to simulate on-disk corruption of an encrypted vault: the file is
    opaque (AES-GCM ciphertext), so we can only damage the bytes and then
    assert the decrypt path refuses to silently produce a fake vault.
    """
    blob = bytearray(path.read_bytes())
    mid = len(blob) // 2
    blob[mid] ^= 0x01
    path.write_bytes(bytes(blob))
    return mid


# ---------------------------------------------------------------------------
# Base class: isolated vault, env-var swap, env restoration
# ---------------------------------------------------------------------------


class EncryptionE2EBase(unittest.TestCase):
    def setUp(self) -> None:
        self._temp = tempfile.TemporaryDirectory(prefix="dontlie-e2e-")
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
        # Force a fresh import of the storage / signing modules so that
        # their module-level ``DB_PATH`` / ``KEY_DIR`` (computed from the
        # env at *import* time) point at this test's temp directory.
        # A bare ``from dontlie import storage`` returns the cached
        # module and would silently keep the first test's path; that's
        # a real problem for the multi-file decrypt-and-rebind flow in
        # these tests.
        from dontlie import sign as signing  # noqa: WPS433
        from dontlie import storage  # noqa: WPS433
        if "dontlie.sign" in sys.modules:
            importlib.reload(signing)
        if "dontlie.storage" in sys.modules:
            importlib.reload(storage)
        self.signing = signing
        self.storage = storage
        # Fresh key + schema for this test.
        signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
        for p in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
            if p.exists():
                p.unlink()
        signing.generate()
        storage.init()
        # Wipe any leftover rows from a previous run.
        conn = storage._connect()
        try:
            conn.execute("DELETE FROM receipts")
            conn.execute("DELETE FROM key_history")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
            conn.commit()
        finally:
            conn.close()
        self._root = root

    def tearDown(self) -> None:
        try:
            for k, v in self._orig_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
        finally:
            self._temp.cleanup()

    # -- helpers -----------------------------------------------------------

    def _sign_n(self, n: int, *, model: str = "gpt-4o-mini") -> list:
        """Append ``n`` receipts and return the list of Receipt objects."""
        receipts = []
        for i in range(n):
            r = self.storage.append(
                model=model,
                prompt=f"prompt-{i:04d}",
                response=f"response-{i:04d}",
            )
            receipts.append(r)
        return receipts

    def _rebind_db(self, db_path: Path) -> None:
        """Point the live ``storage`` module at ``db_path`` and re-init.

        ``storage.DB_PATH`` is a module-level constant evaluated at
        import time, so we have to ``importlib.reload`` the module after
        swapping ``DONTLIE_DB`` to force the new path to take effect.
        This isolates each test's verify from the previous test's state
        and lets the multi-vault (decrypt-then-verify) flow work.
        """
        os.environ["DONTLIE_DB"] = str(db_path)
        from dontlie import storage as fresh_storage  # noqa: WPS433
        if "dontlie.storage" in sys.modules:
            importlib.reload(fresh_storage)
        self.storage = fresh_storage
        fresh_storage.init()


# ---------------------------------------------------------------------------
# 1. Full round-trip: sign 100, encrypt, decrypt, verify all 100 OK.
# ---------------------------------------------------------------------------


class RoundTripTest(EncryptionE2EBase):
    def test_encrypt_decrypt_roundtrip_preserves_chain(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        # Sign 100 receipts into the unencrypted vault.
        self._sign_n(100)
        ok, bad = self.storage.verify_chain()
        self.assertEqual((ok, bad), (100, 0))
        # Encrypt the vault, then decrypt to a fresh location.
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        dec_path = self._root / "vault.decrypted.db"
        passphrase = "roundtrip-pass-001"
        encryption.encrypt_file(vault, enc_path, passphrase.encode("utf-8"))
        encryption.decrypt_file(enc_path, dec_path, passphrase.encode("utf-8"))
        self.assertTrue(enc_path.exists())
        self.assertTrue(dec_path.exists())
        self.assertNotEqual(enc_path.read_bytes(), vault.read_bytes(),
                            "encrypted file must not equal plaintext vault")
        # The decrypted file is byte-identical to the original vault.
        self.assertEqual(dec_path.read_bytes(), vault.read_bytes(),
                         "decrypt must be bit-exact for the right passphrase")
        # Now point the storage layer at the decrypted vault and verify.
        self._rebind_db(dec_path)
        ok2, bad2 = self.storage.verify_chain()
        self.assertEqual((ok2, bad2), (100, 0),
                         "all 100 receipts must verify after decrypt")


# ---------------------------------------------------------------------------
# 2. Tamper detection after decrypt: 100 receipts, edit one row, verify
# ---------------------------------------------------------------------------


class TamperAfterDecryptTest(EncryptionE2EBase):
    def test_tamper_in_decrypted_vault_breaks_verification(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        # Sign 100 receipts, encrypt, then decrypt to a working SQLite file.
        self._sign_n(100)
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        dec_path = self._root / "vault.decrypted.db"
        passphrase = "tamper-pass-002"
        encryption.encrypt_file(vault, enc_path, passphrase.encode("utf-8"))
        encryption.decrypt_file(enc_path, dec_path, passphrase.encode("utf-8"))
        # Sanity: decrypted vault still has all 100 receipts and they verify.
        self.assertEqual(self.storage.count(), 100)
        # Tamper with one receipt's response column in the decrypted SQLite
        # file. We edit the *decrypted* file (the encrypted file is opaque
        # bytes; tampering with it is the separate corruption test). This
        # simulates an attacker who has the passphrase and writes to the
        # plaintext vault, or a decryption workflow where the unlocked
        # vault is then modified before re-verification.
        target_id = 42
        conn = sqlite3.connect(dec_path)
        try:
            # Confirm the row we are about to tamper with.
            row = conn.execute(
                "SELECT response FROM receipts WHERE id = ?", (target_id,)
            ).fetchone()
            self.assertIsNotNone(row)
            conn.execute(
                "UPDATE receipts SET response = ? WHERE id = ?",
                ("TAMPERED-FORGERY", target_id),
            )
            conn.commit()
        finally:
            conn.close()
        # Repoint storage at the tampered decrypted vault and verify.
        self._rebind_db(dec_path)
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 99,
                         "the 99 untampered receipts must still verify")
        self.assertEqual(bad, 1,
                         "the tampered receipt must be flagged as bad")


# ---------------------------------------------------------------------------
# 3. Wrong passphrase: must raise DecryptionError, must not produce a file
# ---------------------------------------------------------------------------


class WrongPassphraseTest(EncryptionE2EBase):
    def test_wrong_passphrase_decryption_fails(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        self._sign_n(10)
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        out_path = self._root / "vault.wrong.db"
        right = "right-passphrase-aaa"
        wrong = "wrong-passphrase-bbb"
        encryption.encrypt_file(vault, enc_path, right.encode("utf-8"))
        with self.assertRaises(encryption.DecryptionError):
            encryption.decrypt_file(enc_path, out_path, wrong.encode("utf-8"))
        # The auth-tag failure must happen BEFORE the target is written:
        # we must never leave a partial "looks-decrypted" vault on disk.
        self.assertFalse(out_path.exists(),
                         "wrong-passphrase decrypt must not create the target file")


# ---------------------------------------------------------------------------
# 4. Byte-exact round-trip: signatures survive encrypt -> decrypt
# ---------------------------------------------------------------------------


class BytesExactTest(EncryptionE2EBase):
    def test_encryption_at_rest_round_trip(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        # 5 receipts is enough to prove the property; the chain length
        # is not what this test cares about.
        receipts = self._sign_n(5)
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        dec_path = self._root / "vault.decrypted.db"
        passphrase = "bytes-exact-pass-004"
        encryption.encrypt_file(vault, enc_path, passphrase.encode("utf-8"))
        encryption.decrypt_file(enc_path, dec_path, passphrase.encode("utf-8"))
        # The decrypted file is byte-identical to the original vault.
        self.assertEqual(dec_path.read_bytes(), vault.read_bytes())
        # All 5 receipts are present and their signatures are intact.
        self._rebind_db(dec_path)
        ok, bad = self.storage.verify_chain()
        self.assertEqual((ok, bad), (5, 0))
        # Pin every original signature and hash to confirm we got the
        # exact same bytes back, not a re-signing.
        for original in receipts:
            roundtripped = self.storage.get_receipt(original.id)
            self.assertIsNotNone(roundtripped)
            self.assertEqual(roundtripped.payload_sha256, original.payload_sha256,
                             f"payload_sha256 changed for id={original.id}")
            self.assertEqual(roundtripped.signature, original.signature,
                             f"signature changed for id={original.id}")
            self.assertEqual(roundtripped.prompt, original.prompt)
            self.assertEqual(roundtripped.response, original.response)


# ---------------------------------------------------------------------------
# 5. CLI subprocess: dontlie encrypt, dontlie unlock, dontlie verify
# ---------------------------------------------------------------------------


class CLISubprocessTest(EncryptionE2EBase):
    def test_dontlie_cli_encrypt_and_unlock(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        # Sign 7 receipts so the verify count is informative but not huge.
        self._sign_n(7)
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        dec_path = self._root / "vault.decrypted.db"

        env = {
            **os.environ,
            "DONTLIE_ENCRYPTION_PASSPHRASE": "cli-e2e-pass-005",
        }
        # Strip any leftover DONTLIE_DB to be sure we drive the CLI
        # via the explicit positional arg. The base class already set it,
        # so this is just a belt-and-braces move.
        env.pop("DONTLIE_DB", None)

        # 1. `dontlie encrypt <vault> --output <enc>`.
        r1 = subprocess.run(
            [sys.executable, "-m", "dontlie", "encrypt",
             str(vault), "--output", str(enc_path)],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r1.returncode, 0,
                         f"encrypt failed: stdout={r1.stdout!r} stderr={r1.stderr!r}")
        self.assertTrue(enc_path.exists())

        # 2. `dontlie unlock <enc> --output <dec> --force`.
        r2 = subprocess.run(
            [sys.executable, "-m", "dontlie", "unlock",
             str(enc_path), "--output", str(dec_path), "--force"],
            env=env, capture_output=True, text=True,
        )
        self.assertEqual(r2.returncode, 0,
                         f"unlock failed: stdout={r2.stdout!r} stderr={r2.stderr!r}")
        self.assertTrue(dec_path.exists())
        self.assertEqual(dec_path.read_bytes(), vault.read_bytes(),
                         "CLI decrypt must be byte-exact")

        # 3. `dontlie verify` against the decrypted vault. We point
        # DONTLIE_DB at the decrypted file for this subprocess call.
        verify_env = {**env, "DONTLIE_DB": str(dec_path)}
        r3 = subprocess.run(
            [sys.executable, "-m", "dontlie", "verify"],
            env=verify_env, capture_output=True, text=True,
        )
        # cmd_verify returns 0 on all-ok, 2 on any bad receipts.
        self.assertEqual(r3.returncode, 0,
                         f"verify failed: stdout={r3.stdout!r} stderr={r3.stderr!r}")
        self.assertIn("7 ok", r3.stdout,
                      f"verify must report 7 ok: {r3.stdout!r}")
        self.assertIn("0 bad", r3.stdout,
                      f"verify must report 0 bad: {r3.stdout!r}")

    def test_dontlie_cli_unlock_with_wrong_passphrase_returns_3(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        self._sign_n(3)
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        out_path = self._root / "vault.bad.db"

        right_env = {
            **os.environ,
            "DONTLIE_ENCRYPTION_PASSPHRASE": "rightpw-005",
        }
        right_env.pop("DONTLIE_DB", None)
        r_enc = subprocess.run(
            [sys.executable, "-m", "dontlie", "encrypt",
             str(vault), "--output", str(enc_path)],
            env=right_env, capture_output=True, text=True,
        )
        self.assertEqual(r_enc.returncode, 0, r_enc.stderr)

        # Wrong passphrase -> CLI must refuse and NOT write the target.
        wrong_env = {
            **os.environ,
            "DONTLIE_ENCRYPTION_PASSPHRASE": "wrongpw-005",
        }
        wrong_env.pop("DONTLIE_DB", None)
        r_unlock = subprocess.run(
            [sys.executable, "-m", "dontlie", "unlock",
             str(enc_path), "--output", str(out_path), "--force"],
            env=wrong_env, capture_output=True, text=True,
        )
        # cmd_unlock returns 3 on EncryptionError.
        self.assertEqual(r_unlock.returncode, 3,
                         f"expected rc=3, got {r_unlock.returncode}; "
                         f"stdout={r_unlock.stdout!r} stderr={r_unlock.stderr!r}")
        self.assertIn("FAIL", r_unlock.stderr)
        self.assertFalse(out_path.exists(),
                         "wrong-passphrase unlock must not write the target file")


# ---------------------------------------------------------------------------
# 6. Regression: an unencrypted vault still works (encryption is opt-in)
# ---------------------------------------------------------------------------


class UnencryptedRegressionTest(EncryptionE2EBase):
    def test_unencrypted_vault_still_works(self) -> None:
        # Do NOT encrypt. Just sign and verify. This catches any change
        # in storage.init() or verify_chain() that would have started
        # demanding an encryption state to be present.
        self._sign_n(10)
        self.assertEqual(self.storage.count(), 10)
        ok, bad = self.storage.verify_chain()
        self.assertEqual(ok, 10)
        self.assertEqual(bad, 0)


# ---------------------------------------------------------------------------
# 7. Corruption resilience: a flipped byte in the encrypted file fails clean
# ---------------------------------------------------------------------------


class CorruptionResilienceTest(EncryptionE2EBase):
    def test_encrypted_vault_resilient_to_corruption(self) -> None:
        if not _argon2_available():
            self.skipTest("argon2-cffi not installed")
        self._sign_n(10)
        vault = Path(os.environ["DONTLIE_DB"])
        enc_path = self._root / "vault.db.enc"
        out_path = self._root / "vault.corrupt.db"
        passphrase = "corrupt-pass-007"
        encryption.encrypt_file(vault, enc_path, passphrase.encode("utf-8"))
        # Flip a single bit in the middle of the encrypted file. AES-GCM
        # is authenticated: this must fail authentication, never silently
        # produce a different but readable vault.
        flipped_at = _flip_byte_in_middle(enc_path)
        # A clean failure is required — and the test must NOT have to
        # catch a generic Exception. Either EncryptionError (caught
        # directly) or its subclass DecryptionError are the documented
        # failure modes. Use DecryptionError because that is the actual
        # path a wrapped-dek or payload-CT byte flip takes through
        # the current code (aesgcm raises InvalidTag -> rewrapped as
        # DecryptionError in _aes_gcm_decrypt).
        with self.assertRaises(encryption.DecryptionError):
            encryption.decrypt_file(enc_path, out_path, passphrase.encode("utf-8"))
        # The target must not have been written; otherwise an attacker
        # who can flip bits in the encrypted file could trick a careless
        # user into trusting a fabricated vault.
        self.assertFalse(out_path.exists(),
                         f"corruption must not yield a target file (flipped offset {flipped_at})")


if __name__ == "__main__":
    unittest.main(verbosity=2)
