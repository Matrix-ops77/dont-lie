"""Command line interface for local public attestations."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .core import (
    AttestationError,
    ReputationStore,
    build_attestation,
    build_revocation,
    check,
    load_private_key,
    load_public_fingerprint,
)


def _default_key() -> Path:
    import os

    key_dir = Path(
        os.environ.get(
            "DONTLIE_KEY_DIR",
            str(Path.home() / ".config/dontlie/keys"),
        )
    )
    return key_dir / "dontlie.key"


def _default_db() -> Path:
    import os

    return Path(
        os.environ.get(
            "DONTLIE_DB",
            str(Path.home() / ".local/share/dontlie/vault.db"),
        )
    )


def _receipt_and_tip(db_path: Path, receipt_id: int) -> tuple[int, str]:
    try:
        with closing(
            sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        ) as connection:
            receipt = connection.execute(
                "SELECT id FROM receipts WHERE id = ?", (receipt_id,)
            ).fetchone()
            tip = connection.execute(
                "SELECT payload_sha256 FROM receipts ORDER BY id DESC LIMIT 1"
            ).fetchone()
    except sqlite3.Error as exc:
        raise AttestationError(f"cannot read receipt vault: {exc}") from exc
    if receipt is None:
        raise AttestationError(f"receipt {receipt_id} not found")
    if tip is None:
        raise AttestationError("receipt vault is empty")
    return int(receipt[0]), str(tip[0])


def _parse_time(value: str | None) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationError("time must be ISO-8601") from exc
    if parsed.tzinfo is None:
        raise AttestationError("time must include a timezone")
    return parsed.astimezone(timezone.utc)


def _private_key(args: argparse.Namespace) -> Ed25519PrivateKey:
    return load_private_key(Path(args.key))


def cmd_publish(args: argparse.Namespace) -> int:
    receipt_id, chain_tip_hash = _receipt_and_tip(Path(args.db), args.receipt_id)
    corroborated = _parse_time(args.last_corroboration)
    if args.witness_count == 0 and corroborated is not None:
        raise AttestationError("--last-corroboration requires at least one witness")
    if args.witness_count > 0 and corroborated is None:
        raise AttestationError("witnessed publication requires --last-corroboration")
    attestation = build_attestation(
        receipt_id=receipt_id,
        chain_tip_hash=chain_tip_hash,
        private_key=_private_key(args),
        witness_count=args.witness_count,
        last_corroboration=corroborated,
    )
    path = ReputationStore(Path(args.store) if args.store else None).put(attestation)
    print(f"published: {attestation.address}")
    print(f"link:      {attestation.link}")
    print(f"artifact:  {path}")
    return 0


def cmd_revoke(args: argparse.Namespace) -> int:
    store = ReputationStore(Path(args.store) if args.store else None)
    attestation = store.resolve(args.reference)
    revocation = build_revocation(attestation, _private_key(args))
    path = store.put_revocation(revocation, attestation)
    print(f"revoked:    {attestation.link}")
    print(f"revocation: {revocation.address}")
    print(f"artifact:   {path}")
    return 0


def cmd_link(args: argparse.Namespace) -> int:
    store = ReputationStore(Path(args.store) if args.store else None)
    print(store.resolve(args.reference).link)
    return 0


def _format_age(seconds: int) -> str:
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m"
    if seconds < 86400:
        return f"{seconds // 3600}h"
    return f"{seconds // 86400}d"


def cmd_check(args: argparse.Namespace) -> int:
    store = ReputationStore(Path(args.store) if args.store else None)
    attestation = store.resolve(args.reference)
    trusted = frozenset(load_public_fingerprint(value) for value in args.trusted_key)
    self_key = None
    key_path = Path(args.key)
    if key_path.is_file():
        self_key = load_private_key(key_path).public_key()
    result = check(
        attestation,
        store=store,
        trusted_fingerprints=trusted,
        self_public_key=self_key,
    )
    corroboration = attestation.last_corroboration
    print(f"trust state:         {'REVOKED' if result.revoked else 'ACTIVE'}")
    print(f"signer trust:        {result.signer_trust}")
    print(f"signer fingerprint:  {attestation.signer_fingerprint}")
    print(f"witness count:       {attestation.payload['witness_count']}")
    print(f"age:                 {_format_age(result.age_seconds)}")
    print(
        "last corroboration: "
        + (corroboration.isoformat() if corroboration else "none")
    )
    print(f"receipt id:          {attestation.payload['receipt_id']}")
    print(f"chain tip:           {attestation.payload['chain_tip_hash']}")
    return 2 if result.revoked else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m reputation",
        description="Publish and verify local, signed public receipt attestations.",
    )
    parser.add_argument("--store", help="content-addressed reputation store")
    parser.add_argument("--key", default=str(_default_key()), help="Ed25519 private PEM")
    subparsers = parser.add_subparsers(dest="command", required=True)

    publish = subparsers.add_parser("publish", help="publish a receipt attestation")
    publish.add_argument("receipt_id", type=int)
    publish.add_argument("--db", default=str(_default_db()), help="Don't-Lie SQLite vault")
    publish.add_argument("--witness-count", type=int, default=0)
    publish.add_argument(
        "--last-corroboration",
        help="ISO-8601 time of the latest witness corroboration",
    )
    publish.set_defaults(handler=cmd_publish)

    revoke = subparsers.add_parser("revoke", help="revoke an attestation")
    revoke.add_argument("reference", help="link, content hash, or artifact path")
    revoke.set_defaults(handler=cmd_revoke)

    link = subparsers.add_parser("link", help="print the short share fragment")
    link.add_argument("reference", help="link, content hash, or artifact path")
    link.set_defaults(handler=cmd_link)

    inspect = subparsers.add_parser("check", help="show offline trust state")
    inspect.add_argument("reference", help="link, content hash, or artifact path")
    inspect.add_argument(
        "--trusted-key",
        action="append",
        default=[],
        help="pinned Ed25519 public PEM path or raw base64url key",
    )
    inspect.set_defaults(handler=cmd_check)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (AttestationError, OSError) as exc:
        print(f"reputation: {exc}", file=sys.stderr)
        return 1
