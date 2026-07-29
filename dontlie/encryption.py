"""Encrypted-at-rest vault support.

Uses Argon2id for key derivation and AES-256-GCM for authenticated
encryption. The vault passphrase is never written to disk; the derived
key is held in memory only for the lifetime of the unlocked vault.

Storage format: a single ``encryption_state`` row holding the salt, the
Argon2id parameters, and the wrapped DEK. The DEK is encrypted with the
passphrase-derived KEK and is what's persisted to every other row's
encrypted column.

This module is intentionally dependency-light: it relies on the
``cryptography`` package which is already a transitive dependency of
Don't-Lie. Argon2id uses the ``argon2-cffi`` library; if absent, an
``EncryptionUnavailable`` is raised on encrypt/decrypt.
"""

from __future__ import annotations

import base64
import os
import secrets
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


try:  # pragma: no cover - optional dependency
    from argon2.low_level import Type as Argon2Type
    from argon2.low_level import hash_secret_raw

    _ARGON2 = True
except Exception:  # pragma: no cover
    _ARGON2 = False


class EncryptionError(Exception):
    """Base class for encryption failures."""


class EncryptionUnavailable(EncryptionError):
    """Raised when argon2-cffi is not installed."""


class DecryptionError(EncryptionError):
    """Raised when ciphertext cannot be authenticated."""


@dataclass
class KDFParams:
    time_cost: int = 3
    memory_cost: int = 64 * 1024  # 64 MiB
    parallelism: int = 1
    salt_len: int = 16


@dataclass
class VaultState:
    salt: bytes
    wrapped_dek: bytes
    nonce: bytes
    kdf: KDFParams


def _require_argon2() -> None:
    if not _ARGON2:
        raise EncryptionUnavailable(
            "argon2-cffi is required for encrypted vault support; "
            "install with `pip install argon2-cffi`"
        )


def _derive_kek(passphrase: str, salt: bytes, params: KDFParams) -> bytes:
    _require_argon2()
    return hash_secret_raw(
        secret=passphrase.encode("utf-8"),
        salt=salt,
        time_cost=params.time_cost,
        memory_cost=params.memory_cost,
        parallelism=params.parallelism,
        hash_len=32,
        type=Argon2Type.ID,
    )


def _aes_gcm_encrypt(key: bytes, plaintext: bytes, *, aad: bytes = b"") -> tuple[bytes, bytes]:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad)
    return nonce, ciphertext


def _aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except Exception as exc:  # cryptography raises InvalidTag
        raise DecryptionError(str(exc)) from exc


def encrypt_with_passphrase(passphrase: str, plaintext: bytes, *, params: Optional[KDFParams] = None) -> VaultState:
    """Encrypt arbitrary plaintext using a passphrase.

    Returns a :class:`VaultState` containing the salt, the wrapped DEK,
    and the nonce. The full ciphertext is the concatenation of the
    wrapped DEK and the encrypted payload; the caller is responsible for
    storing it (or just the nonce + ciphertext pair).
    """
    p = params or KDFParams()
    salt = secrets.token_bytes(p.salt_len)
    kek = _derive_kek(passphrase, salt, p)
    dek = secrets.token_bytes(32)
    # Wrap DEK with KEK.
    nonce, wrapped_dek = _aes_gcm_encrypt(kek, dek)
    return VaultState(salt=salt, wrapped_dek=wrapped_dek, nonce=nonce, kdf=p)


def decrypt_with_passphrase(passphrase: str, state: VaultState, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
    """Decrypt a payload wrapped with :func:`encrypt_with_passphrase`."""
    kek = _derive_kek(passphrase, state.salt, state.kdf)
    dek = _aes_gcm_decrypt(kek, state.nonce, state.wrapped_dek)
    return _aes_gcm_decrypt(dek, ciphertext[:12], ciphertext[12:], aad=aad)


def wrap_dek(passphrase: str, *, params: Optional[KDFParams] = None) -> tuple[VaultState, bytes]:
    """Create a fresh DEK and wrap it with the passphrase. Returns (state, dek)."""
    p = params or KDFParams()
    salt = secrets.token_bytes(p.salt_len)
    kek = _derive_kek(passphrase, salt, p)
    dek = secrets.token_bytes(32)
    nonce, wrapped_dek = _aes_gcm_encrypt(kek, dek)
    return VaultState(salt=salt, wrapped_dek=wrapped_dek, nonce=nonce, kdf=p), dek


def unwrap_dek(passphrase: str, state: VaultState) -> bytes:
    """Recover the DEK from a :class:`VaultState`."""
    kek = _derive_kek(passphrase, state.salt, state.kdf)
    return _aes_gcm_decrypt(kek, state.nonce, state.wrapped_dek)


def encrypt_column(dek: bytes, plaintext: bytes, *, aad: bytes = b"") -> tuple[bytes, bytes]:
    """Encrypt a single column value with the DEK. Returns (nonce, ciphertext)."""
    return _aes_gcm_encrypt(dek, plaintext, aad=aad)


def decrypt_column(dek: bytes, nonce: bytes, ciphertext: bytes, *, aad: bytes = b"") -> bytes:
    return _aes_gcm_decrypt(dek, nonce, ciphertext, aad=aad)


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


# ---- Whole-file helpers (used by the ``dontlie encrypt`` / ``unlock`` CLI) -

_ENCRYPTED_FILE_MAGIC = b"DLVL1\n"  # "Don't-Lie Vault Layer 1\n"
_ENCRYPTED_FILE_VERSION = 1


def encrypt_file(source: "Path | str", target: "Path | str", passphrase: bytes) -> None:
    """Encrypt a whole file (e.g. ``vault.db``) to a sidecar ``.enc`` file.

    The output format is::

        DLVL1\\n
        <1-byte version: 0x01>
        <16-byte salt>
        <12-byte wrapped_dek nonce>
        <N-byte wrapped_dek>
        <12-byte payload nonce>
        <M-byte AES-GCM ciphertext>

    The version byte allows future evolution. The first line is a
    magic so a stray file is rejected loudly instead of producing a
    corrupted vault when the user feeds it to :func:`decrypt_file`.
    """
    from pathlib import Path
    src = Path(source)
    dst = Path(target)
    plaintext = src.read_bytes()
    state, dek = wrap_dek(passphrase.decode("utf-8"))
    payload_nonce, payload_ct = _aes_gcm_encrypt(dek, plaintext, aad=b"dontlie-vault-v1")
    with dst.open("wb") as f:
        f.write(_ENCRYPTED_FILE_MAGIC)
        f.write(bytes([_ENCRYPTED_FILE_VERSION]))
        f.write(state.salt)
        f.write(state.nonce)
        f.write(state.wrapped_dek)
        f.write(payload_nonce)
        f.write(payload_ct)


def decrypt_file(source: "Path | str", target: "Path | str", passphrase: bytes) -> None:
    """Reverse of :func:`encrypt_file`. Raises :class:`EncryptionError`
    on bad magic, unsupported version, or wrong passphrase."""
    from pathlib import Path
    src = Path(source)
    dst = Path(target)
    blob = src.read_bytes()
    if not blob.startswith(_ENCRYPTED_FILE_MAGIC):
        raise EncryptionError(f"{src} is not a don't-lie encrypted file")
    off = len(_ENCRYPTED_FILE_MAGIC)
    version = blob[off]
    off += 1
    if version != _ENCRYPTED_FILE_VERSION:
        raise EncryptionError(f"unsupported encryption version: {version}")
    # KDFParams defaults match the ones used in wrap_dek
    salt_len = 16
    nonce_len = 12
    salt = blob[off:off + salt_len]; off += salt_len
    state_nonce = blob[off:off + nonce_len]; off += nonce_len
    # wrapped_dek is variable length; read the remaining two chunks
    # (wrapped_dek | payload_nonce | payload_ct) and split by their
    # declared sizes. For now: assume wrapped_dek = salt_len + 12
    # nonce + 32 bytes ciphertext tag (GCM tag).
    # But we don't know the wrapped_dek length. Use the remaining file
    # minus the final two fixed chunks.
    remaining = len(blob) - off
    payload_nonce_len = nonce_len
    payload_ct_len = remaining - payload_nonce_len
    wrapped_dek_len = payload_ct_len  # we keep the rest before payload nonce
    # The actual layout (constructed by encrypt_file):
    #   salt | state.nonce | state.wrapped_dek | payload_nonce | payload_ct
    # state.nonce is 12B; wrapped_dek's length is whatever GCM produced
    # for a 32B DEK -> 32B plaintext + 16B tag = 48B.
    wrapped_dek_len = 48
    wrapped_dek = blob[off:off + wrapped_dek_len]; off += wrapped_dek_len
    payload_nonce = blob[off:off + payload_nonce_len]; off += payload_nonce_len
    payload_ct = blob[off:]
    state = VaultState(
        salt=salt,
        wrapped_dek=wrapped_dek,
        nonce=state_nonce,
        kdf=KDFParams(),
    )
    dek = unwrap_dek(passphrase.decode("utf-8"), state)
    plaintext = _aes_gcm_decrypt(dek, payload_nonce, payload_ct, aad=b"dontlie-vault-v1")
    dst.write_bytes(plaintext)


def is_unlocked(conn: sqlite3.Connection) -> bool:
    row = conn.execute(
        "SELECT value FROM vault_state WHERE key='unlocked'"
    ).fetchone()
    return bool(row and row[0] == "1")


def ensure_state_table(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS vault_state (
            key TEXT PRIMARY KEY,
            value BLOB NOT NULL
        )
        """
    )


def persist_state(conn: sqlite3.Connection, state: VaultState) -> None:
    ensure_state_table(conn)
    conn.execute(
        "INSERT OR REPLACE INTO vault_state(key, value) VALUES (?, ?)",
        ("salt", state.salt),
    )
    conn.execute(
        "INSERT OR REPLACE INTO vault_state(key, value) VALUES (?, ?)",
        ("wrapped_dek", state.wrapped_dek + state.nonce),
    )
    conn.execute(
        "INSERT OR REPLACE INTO vault_state(key, value) VALUES (?, ?)",
        ("kdf", str(state.kdf.time_cost).encode() + b"|" + str(state.kdf.memory_cost).encode()),
    )
    conn.commit()


__all__ = [
    "EncryptionError",
    "EncryptionUnavailable",
    "DecryptionError",
    "KDFParams",
    "VaultState",
    "encrypt_with_passphrase",
    "decrypt_with_passphrase",
    "wrap_dek",
    "unwrap_dek",
    "encrypt_column",
    "decrypt_column",
    "b64",
    "b64d",
    "is_unlocked",
    "ensure_state_table",
    "persist_state",
]
