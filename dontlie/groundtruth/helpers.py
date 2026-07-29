"""Shared helpers for the groundtruth lane.

Lives in its own module so that envelope.py, client.py, and verifier.py
can import the same nonce/digest helpers without circular imports.
"""

from __future__ import annotations

import hashlib
import secrets


def short_nonce(nbytes: int = 8) -> str:
    """Return a short URL/user-friendly nonce (>= 8 chars by default)."""
    raw = secrets.token_hex(max(4, nbytes // 2))
    return raw[:64] if len(raw) > 64 else raw


def digest_payload(value: str) -> str:
    """Canonical SHA-256 over a stringified payload; returns 64 hex chars."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


__all__ = ["digest_payload", "short_nonce"]
