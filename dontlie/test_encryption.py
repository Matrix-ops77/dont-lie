"""Focused tests for the encrypted vault module.

The module exposes two layers:

1. **PBE (passphrase-based) encryption** — Argon2id → KEK → wrap a random DEK
   → encrypt payload with the DEK (AES-256-GCM). Requires ``argon2-cffi``.
2. **Column-level encryption** — pure AES-256-GCM with a caller-supplied
   DEK. Requires only ``cryptography``.

These tests focus on the file-level (``encrypt_with_passphrase`` /
``decrypt_with_passphrase``) and column-level (encrypt_column /
decrypt_column) APIs, plus the DEK wrapping primitives. Argon2 tests are
skipped when ``argon2-cffi`` is not installed.
"""

from __future__ import annotations

import secrets
import sqlite3
import tempfile
import unittest
from pathlib import Path

import dontlie.encryption as encryption
from dontlie.encryption import (
    DecryptionError,
    EncryptionError,
    EncryptionUnavailable,
    KDFParams,
    b64,
    b64d,
    decrypt_column,
    decrypt_with_passphrase,
    encrypt_column,
    encrypt_with_passphrase,
    ensure_state_table,
    persist_state,
    unwrap_dek,
    wrap_dek,
)


def _argon2_available() -> bool:
    try:
        import argon2.low_level  # noqa: F401
        return True
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_params() -> KDFParams:
    """Light KDF params so tests run fast. SECURITY: only for tests."""
    return KDFParams(time_cost=1, memory_cost=8 * 1024, parallelism=1, salt_len=16)


# ---------------------------------------------------------------------------
# Pure column-level AES-GCM (no Argon2 dependency)
# ---------------------------------------------------------------------------


class ColumnEncryptionTest(unittest.TestCase):
    """encrypt_column / decrypt_column round-trip & tamper detection."""

    def test_round_trip_recovers_plaintext(self) -> None:
        dek = secrets.token_bytes(32)
        nonce, ct = encrypt_column(dek, b"hello-vault")
        self.assertEqual(decrypt_column(dek, nonce, ct), b"hello-vault")

    def test_aad_is_authenticated(self) -> None:
        dek = secrets.token_bytes(32)
        nonce, ct = encrypt_column(dek, b"payload", aad=b"receipt:7")
        # Wrong AAD should fail authentication.
        with self.assertRaises(Exception):
            decrypt_column(dek, nonce, ct, aad=b"receipt:8")
        # Correct AAD recovers plaintext.
        self.assertEqual(
            decrypt_column(dek, nonce, ct, aad=b"receipt:7"),
            b"payload",
        )

    def test_tampered_ciphertext_raises(self) -> None:
        dek = secrets.token_bytes(32)
        nonce, ct = encrypt_column(dek, b"original")
        tampered = bytearray(ct)
        tampered[0] ^= 0x01
        with self.assertRaises(Exception):
            decrypt_column(dek, nonce, bytes(tampered))

    def test_wrong_key_fails(self) -> None:
        dek = secrets.token_bytes(32)
        nonce, ct = encrypt_column(dek, b"secret")
        with self.assertRaises(Exception):
            decrypt_column(secrets.token_bytes(32), nonce, ct)

    def test_nonce_is_unique_per_call(self) -> None:
        dek = secrets.token_bytes(32)
        n1, _ = encrypt_column(dek, b"same")
        n2, _ = encrypt_column(dek, b"same")
        self.assertNotEqual(n1, n2)
        self.assertEqual(len(n1), 12)


class B64Test(unittest.TestCase):
    def test_round_trip(self) -> None:
        data = secrets.token_bytes(48)
        self.assertEqual(b64d(b64(data)), data)


# ---------------------------------------------------------------------------
# PBE / Argon2id tests — skip if argon2-cffi is missing
# ---------------------------------------------------------------------------


@unittest.skipUnless(_argon2_available(), "argon2-cffi not installed")
class PassphraseEncryptionTest(unittest.TestCase):
    """High-level encrypt_with_passphrase / decrypt_with_passphrase."""

    def test_round_trip_through_pbe(self) -> None:
        passphrase = "correct horse battery staple"
        plaintext = b"don't lie to me, receipt vault"
        state = encrypt_with_passphrase(passphrase, plaintext, params=_make_params())
        # unwrap_dek should recover the DEK used to encrypt the payload.
        recovered_dek = unwrap_dek(passphrase, state)
        self.assertEqual(len(recovered_dek), 32)
        nonce, ct = encrypt_column(recovered_dek, plaintext)
        # decrypt_with_passphrase consumes (nonce || ciphertext).
        decrypted = decrypt_with_passphrase(
            passphrase, state, nonce + ct
        )
        self.assertEqual(decrypted, plaintext)

    def test_wrong_passphrase_fails(self) -> None:
        state = encrypt_with_passphrase(
            "right", b"payload", params=_make_params()
        )
        recovered_dek = unwrap_dek("right", state)
        nonce, ct = encrypt_column(recovered_dek, b"payload")
        with self.assertRaises(DecryptionError):
            decrypt_with_passphrase("wrong", state, nonce + ct)

    def test_unique_salt_per_encryption(self) -> None:
        params = _make_params()
        s1 = encrypt_with_passphrase("pw", b"a", params=params)
        s2 = encrypt_with_passphrase("pw", b"a", params=params)
        self.assertNotEqual(s1.salt, s2.salt)
        self.assertNotEqual(s1.nonce, s2.nonce)


@unittest.skipUnless(_argon2_available(), "argon2-cffi not installed")
class WrapUnwrapDekTest(unittest.TestCase):
    def test_wrap_then_unwrap_returns_dek(self) -> None:
        state, dek = wrap_dek("p4ssphrase", params=_make_params())
        self.assertEqual(len(dek), 32)
        recovered = unwrap_dek("p4ssphrase", state)
        self.assertEqual(recovered, dek)

    def test_unwrap_with_wrong_passphrase_raises(self) -> None:
        state, _dek = wrap_dek("right", params=_make_params())
        with self.assertRaises(DecryptionError):
            unwrap_dek("wrong", state)


# ---------------------------------------------------------------------------
# State persistence (no Argon2 dependency)
# ---------------------------------------------------------------------------


class StatePersistenceTest(unittest.TestCase):
    def test_ensure_state_table_is_idempotent(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "vault.db"
            conn = sqlite3.connect(db)
            try:
                ensure_state_table(conn)
                ensure_state_table(conn)  # second call must not raise
                rows = conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_state'"
                ).fetchall()
                self.assertEqual(len(rows), 1)
            finally:
                conn.close()

    @unittest.skipUnless(_argon2_available(), "argon2-cffi not installed")
    def test_persist_state_writes_state_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "vault.db"
            conn = sqlite3.connect(db)
            try:
                state, _dek = wrap_dek("pw", params=_make_params())
                persist_state(conn, state)
                # Salt + wrapped_dek + kdf rows should be present.
                keys = {
                    row[0]
                    for row in conn.execute(
                        "SELECT key FROM vault_state"
                    ).fetchall()
                }
                self.assertIn("salt", keys)
                self.assertIn("wrapped_dek", keys)
                self.assertIn("kdf", keys)
            finally:
                conn.close()


# ---------------------------------------------------------------------------
# Error types
# ---------------------------------------------------------------------------


class ErrorHierarchyTest(unittest.TestCase):
    def test_decryption_error_is_encryption_error(self) -> None:
        self.assertTrue(issubclass(DecryptionError, EncryptionError))

    def test_encryption_unavailable_is_encryption_error(self) -> None:
        self.assertTrue(issubclass(EncryptionUnavailable, EncryptionError))


if __name__ == "__main__":
    unittest.main()
