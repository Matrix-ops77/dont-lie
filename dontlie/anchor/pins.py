"""Pin table for trusted free TSA intermediaries.

Don't-Lie pins the SHA-256 of each TSA's signing certificate DER so a
network attacker cannot substitute a different TSA's response. Operators
populate the pin on first deploy by fetching the TSA's cert over HTTPS
and storing its SHA-256 in the ``DONTLIE_TSA_<NAME>_CERT_SHA256`` env
var, or via the ``set_pin`` API at runtime.

The pin table is intentionally empty by default — there is no way to
discover a free TSA's signing-cert fingerprint without a live HTTPS
fetch, and hardcoding any value here would itself be a trust claim.
The verify path drops an attestation whose cert is not pinned, so an
operator who has not yet pinned a TSA simply receives bundles without
RFC 3161 anchors until they do.
"""

from __future__ import annotations

import hashlib
import os
from collections.abc import Iterable
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TSAEntry:
    """One trusted Time Stamping Authority."""

    name: str
    url: str
    # SHA-256 of the TSA's signing certificate DER, hex-encoded.
    # Empty set means "no pins yet — attestations will be dropped on verify".
    cert_sha256: frozenset[str] = field(default_factory=frozenset)


_TABLE: dict[str, TSAEntry] = {
    "freetsa": TSAEntry(
        name="freetsa",
        url="https://freetsa.org/tsr",
    ),
    "digistamp": TSAEntry(
        name="digistamp",
        url="https://timestamp.digicert.com",
    ),
    "sectigo": TSAEntry(
        name="sectigo",
        url="https://timestamp.sectigo.com",
    ),
}


def _load_env_pins() -> None:
    """Overlay environment-supplied pins on top of the static table.

    Recognized variables:
      DONTLIE_TSA_URL                       override default TSA URL
      DONTLIE_TSA_FREETSA_CERT_SHA256       comma-separated hex pins
      DONTLIE_TSA_DIGISTAMP_CERT_SHA256     comma-separated hex pins
      DONTLIE_TSA_SECTIGO_CERT_SHA256       comma-separated hex pins
    """
    url_override = os.environ.get("DONTLIE_TSA_URL")
    for name, entry in _TABLE.items():
        env_key = f"DONTLIE_TSA_{name.upper()}_CERT_SHA256"
        env_val = os.environ.get(env_key)
        pins = _parse_pin_list(env_val) if env_val else frozenset()
        # Always rebuild the entry so the frozen dataclass picks up env.
        _TABLE[name] = TSAEntry(
            name=entry.name,
            url=entry.url,
            cert_sha256=entry.cert_sha256 | pins,
        )
    if url_override:
        # The override replaces the default URL but keeps that name.
        current = _TABLE.get("freetsa")
        if current is not None:
            _TABLE["freetsa"] = TSAEntry(
                name=current.name,
                url=url_override,
                cert_sha256=current.cert_sha256,
            )


def _parse_pin_list(raw: str) -> frozenset[str]:
    out: set[str] = set()
    for chunk in raw.split(","):
        chunk = chunk.strip().lower()
        if not chunk:
            continue
        if len(chunk) != 64 or any(c not in "0123456789abcdef" for c in chunk):
            raise ValueError(f"invalid SHA-256 pin: {chunk!r}")
        out.add(chunk)
    return frozenset(out)


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def set_pin(name: str, cert_der: bytes | str) -> str:
    """Add a pin for ``name`` from DER bytes or an existing hex string.

    Returns the hex pin that was added. Raises ``KeyError`` if the
    TSA name is unknown.
    """
    entry = _TABLE.get(name)
    if entry is None:
        raise KeyError(f"unknown TSA: {name!r}")
    if isinstance(cert_der, str):
        pin = cert_der.lower()
        if len(pin) != 64 or any(
            c not in "0123456789abcdef" for c in pin
        ):
            raise ValueError(f"invalid SHA-256 hex: {pin!r}")
    else:
        pin = _sha256_hex(cert_der)
    _TABLE[name] = TSAEntry(
        name=entry.name,
        url=entry.url,
        cert_sha256=entry.cert_sha256 | {pin},
    )
    return pin


def clear_pins(name: str) -> None:
    """Remove all pins for ``name`` (useful for tests)."""
    entry = _TABLE.get(name)
    if entry is None:
        return
    _TABLE[name] = TSAEntry(
        name=entry.name, url=entry.url, cert_sha256=frozenset()
    )


def get_entry(name: str) -> TSAEntry:
    entry = _TABLE.get(name)
    if entry is None:
        raise KeyError(f"unknown TSA: {name!r}")
    return entry


def default_tsa() -> TSAEntry:
    """Return the default TSA (freetsa, possibly env-overridden)."""
    return _TABLE["freetsa"]


def find_by_url(url: str) -> TSAEntry | None:
    for entry in _TABLE.values():
        if entry.url == url:
            return entry
    return None


def all_entries() -> Iterable[TSAEntry]:
    """Return every configured TSA entry (for introspection)."""
    return tuple(_TABLE.values())


# Load env-supplied pins on first import so verification picks them up.
_load_env_pins()
