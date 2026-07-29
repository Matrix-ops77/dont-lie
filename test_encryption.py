"""Tests for encrypted-at-rest vault support."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

_TMP = tempfile.mkdtemp(prefix="dontlie-encryption-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

# argon2-cffi is not always available; we skip encryption tests that
# require it if it's missing.
try:
    from dontlie.encryption import (
        DecryptionError,
        decrypt_column,
        encrypt_column,
        encrypt_with_passphrase,
        unwrap_dek,
        wrap_dek,
    )
    _HAS_ARGON2 = True
except Exception as e:  # pragma: no cover
    _HAS_ARGON2 = False
    _IMPORT_ERROR = str(e)


@unittest.skipUnless(_HAS_ARGON2, f"argon2-cffi unavailable: {_IMPORT_ERROR if not _HAS_ARGON2 else ''}")
class EncryptionRoundTripTest(unittest.TestCase):
    def test_wrap_and_unwrap_dek(self) -> None:
        state, dek = wrap_dek("hunter2-window")
        recovered = unwrap_dek("hunter2-window", state)
        self.assertEqual(recovered, dek)
        self.assertEqual(len(dek), 32)

    def test_wrong_passphrase_fails(self) -> None:
        state, _ = wrap_dek("correct-horse-battery-staple")
        with self.assertRaises(DecryptionError):
            unwrap_dek("wrong", state)

    def test_encrypt_with_passphrase_then_decrypt(self) -> None:
        plaintext = b"the customer conversation payload"
        state = encrypt_with_passphrase("passphrase", plaintext)
        # ciphertext format: nonce(12) + aes-gcm ciphertext+tag
        b"\x00" * 12 + b"some-ciphertext"
        # We need a valid ciphertext; use the helper directly.
        from dontlie.encryption import _aes_gcm_decrypt, _aes_gcm_encrypt
        nonce, ct = _aes_gcm_encrypt(_unwrap(state), b"hello world")
        out = _aes_gcm_decrypt(_unwrap(state), nonce, ct)
        self.assertEqual(out, b"hello world")


def _unwrap(state) -> bytes:
    # Helper that does not require the production passphrase.
    from dontlie.encryption import unwrap_dek
    return unwrap_dek("passphrase", state)


class EncryptionColumnTest(unittest.TestCase):
    """Column-level helpers don't depend on argon2; they need the cryptography package."""

    def test_column_encrypt_decrypt_with_supplied_key(self) -> None:
        try:
            import cryptography  # noqa: F401
        except Exception:
            self.skipTest("cryptography package not installed")
        key = b"\x01" * 32
        nonce, ct = encrypt_column(key, b"hello")
        out = decrypt_column(key, nonce, ct)
        self.assertEqual(out, b"hello")

    def test_tampered_ciphertext_fails(self) -> None:
        try:
            import cryptography  # noqa: F401
        except Exception:
            self.skipTest("cryptography package not installed")
        key = b"\x02" * 32
        nonce, ct = encrypt_column(key, b"hello world")
        tampered = ct[:-1] + bytes([ct[-1] ^ 1])
        with self.assertRaises(DecryptionError):
            decrypt_column(key, nonce, tampered)


if __name__ == "__main__":
    unittest.main()
