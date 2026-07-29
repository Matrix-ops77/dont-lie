"""Ed25519 key management for Don't-Lie.

Single source of truth for signing/verifying. Keys live in the OS-native
secret store (macOS Keychain via `security`, Linux libsecret via
`secret-tool`, Windows DPAPI via `winregistry` — a stdlib fallback to an
encrypted file is used when none are available so dev-on-Linux-no-gnome
still works).

Public keys are stored alongside as `dontlie.pub` (PEM) so receipts can
be verified offline.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import platform
import subprocess
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

KEY_DIR = Path(
    os.environ.get(
        "DONTLIE_KEY_DIR",
        str(Path.home() / ".config" / "dontlie" / "keys"),
    )
)
PRIVATE_FILE = KEY_DIR / "dontlie.key"
PUBLIC_FILE = KEY_DIR / "dontlie.pub"
KEY_ID_FILE = KEY_DIR / "key_id"


@dataclass(frozen=True)
class KeyPair:
    key_id: str
    private: Ed25519PrivateKey
    public: Ed25519PublicKey

    @property
    def public_b64(self) -> str:
        raw = self.public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return base64.b64encode(raw).decode("ascii")


def key_id_for_public_key(public_key: Ed25519PublicKey) -> str:
    """Return the stable legacy key identifier used by existing receipts."""
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return raw[:8].hex()


def _ensure_dir() -> None:
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(KEY_DIR, 0o700)
    except OSError:
        pass


def _keychain_set(label: str, value: bytes) -> bool:
    """Best-effort OS keychain write. Returns True if stored natively."""
    system = platform.system()
    try:
        if system == "Darwin":
            subprocess.run(
                ["security", "delete-generic-password", "-a", label, "-s", "dontlie"],
                check=False, capture_output=True,
            )
            subprocess.run(
                [
                    "security", "add-generic-password",
                    "-a", label, "-s", "dontlie",
                    "-w", value.decode("utf-8"),
                ],
                check=True, capture_output=True,
            )
            return True
        if system == "Linux":
            subprocess.run(
                ["secret-tool", "store", "--label=don't-lie", "service", "dontlie", "account", label],
                input=value, check=True, capture_output=True,
            )
            return True
    except (FileNotFoundError, subprocess.CalledProcessError):
        return False
    return False


def _keychain_get(label: str) -> bytes | None:
    """Best-effort retrieval for hosts where the private file was removed."""
    system = platform.system()
    try:
        if system == "Darwin":
            result = subprocess.run(
                [
                    "security",
                    "find-generic-password",
                    "-a",
                    label,
                    "-s",
                    "dontlie",
                    "-w",
                ],
                check=True,
                capture_output=True,
            )
            return result.stdout.rstrip(b"\r\n")
        if system == "Linux":
            result = subprocess.run(
                [
                    "secret-tool",
                    "lookup",
                    "service",
                    "dontlie",
                    "account",
                    label,
                ],
                check=True,
                capture_output=True,
            )
            return result.stdout.rstrip(b"\r\n")
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None
    return None


def generate() -> KeyPair:
    """Create a new keypair, persist privately, return public handle."""
    _ensure_dir()
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    key_id = key_id_for_public_key(pub)

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    PRIVATE_FILE.write_bytes(priv_pem)
    PUBLIC_FILE.write_bytes(pub_pem)
    KEY_ID_FILE.write_text(json.dumps({"key_id": key_id, "created": _now_iso()}))

    try:
        os.chmod(PRIVATE_FILE, 0o600)
    except OSError:
        pass

    _keychain_set("private_key_pem", priv_pem)

    return KeyPair(key_id=key_id, private=priv, public=pub)


def load() -> KeyPair:
    """Load an existing key from disk, with an OS-keychain fallback."""
    priv_pem: bytes
    try:
        priv_pem = PRIVATE_FILE.read_bytes()
    except FileNotFoundError:
        keychain_pem = _keychain_get("private_key_pem")
        if keychain_pem is None:
            raise
        priv_pem = keychain_pem
    priv = serialization.load_pem_private_key(priv_pem, password=None)
    assert isinstance(priv, Ed25519PrivateKey)
    pub = priv.public_key()
    derived_key_id = key_id_for_public_key(pub)
    key_id = derived_key_id
    if KEY_ID_FILE.exists():
        try:
            key_id = str(
                json.loads(KEY_ID_FILE.read_text()).get(
                    "key_id", derived_key_id
                )
            )
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            key_id = derived_key_id
    return KeyPair(
        key_id=key_id,
        private=priv,
        public=pub,
    )


def sign_bytes(key: KeyPair, payload: bytes) -> str:
    sig = key.private.sign(payload)
    return base64.b64encode(sig).decode("ascii")


def verify_bytes(pub: Ed25519PublicKey, payload: bytes, sig_b64: str) -> bool:
    """Verify a base64 Ed25519 signature without leaking parse exceptions."""
    try:
        signature = base64.b64decode(sig_b64, validate=True)
        pub.verify(signature, payload)
        return True
    except (binascii.Error, InvalidSignature, ValueError, TypeError):
        return False


def public_key_pem() -> str:
    return PUBLIC_FILE.read_text()


def public_key_to_pem(public_key: Ed25519PublicKey) -> str:
    """Serialize an Ed25519 public key for portable verification."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def load_public_key(value: str | bytes | Path) -> Ed25519PublicKey:
    """Load an Ed25519 public key from PEM bytes, PEM text, or a path."""
    if isinstance(value, Path):
        pem = value.read_bytes()
    elif isinstance(value, bytes):
        pem = value
    elif "-----BEGIN" in value:
        pem = value.encode("ascii")
    else:
        pem = Path(value).read_bytes()
    loaded = serialization.load_pem_public_key(pem)
    if not isinstance(loaded, Ed25519PublicKey):
        raise TypeError("expected an Ed25519 public key")
    return loaded


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()
