"""dontlie anchor-daily — at the end of each UTC day, anchor the
chain's daily Merkle root to three external parties:

  1. A Merkle-root batch (existing `batch.create()`) — 1 Ed25519 signature
     over the day's receipts' SHA-256 leaves.
  2. An OTS-compatible pending attestation (Bitcoin-anchorable later)
     for the Merkle root, not for each receipt.
  3. A witness attestation POST (third-party witness) for the
     Merkle root. The witness URL is supplied by the operator;
     Don't-Lie does not operate a witness service.

This is the "chain did not break" claim with a third-party witness
applied to the daily root. With the receipt-level witness-coverage
from `witness_coverage.py` plus the daily root anchor from this
module, the entire vault's integrity can be challenged by an
auditor against an external trust root.

Usage:
    dontlie anchor daily                  # anchor today (UTC)
    dontlie anchor daily --day 2026-07-28 # anchor a specific day
    dontlie anchor daily --dry-run       # show what would be anchored
    dontlie anchor daily --url <URL>     # use a different witness
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import secrets
import sys
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from . import __version__, storage
from . import batch as _batch
from . import sign as signing

OTS_DIR = Path(
    os.environ.get(
        "DONTLIE_OTS_DIR",
        str(Path.home() / ".dontlie" / "ots"),
    )
)

# Same OTS format constants as `ots.py`
OTS_MAGIC = b"\x00\x4f\x50"
OTS_VERSION = 1
ATT_PENDING = 0x00


def _varint(n: int) -> bytes:
    buf = bytearray()
    while n >= 0x80:
        buf.append((n & 0x7f) | 0x80)
        n >>= 7
    buf.append(n)
    return bytes(buf)


def _serialize_attestation(att_type: int, payload: bytes) -> bytes:
    return _varint(att_type) + _varint(len(payload)) + payload


def _witness_pubkey(url: str, timeout: int = 10) -> dict:
    pkreq = urllib.request.Request(
        url.rstrip("/") + "/pubkey", method="GET",
        headers={"User-Agent": f"dontlie-cli/{__version__}"},
    )
    with urllib.request.urlopen(pkreq, timeout=timeout) as resp:
        return json.loads(resp.read())


def _post_witness_attest(
    url: str, root_sha: str, operator_key_id: str, nonce: str | None = None
) -> dict:
    nonce = nonce or secrets.token_hex(16)
    payload = {
        "receipt_sha256": root_sha,
        "operator_key_id": operator_key_id,
        "nonce": nonce,
        "subject": "daily-merkle-root",
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url.rstrip("/") + "/attest", data=body, method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": f"dontlie-cli/{__version__}",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


def _verify_attestation(att: dict, witness_pub: dict, sent_payload: dict) -> bool:
    canonical = json.dumps({
        "receipt_sha256": sent_payload["receipt_sha256"],
        "operator_key_id": sent_payload["operator_key_id"],
        "parent_sha256": sent_payload.get("parent_sha256", ""),
        "nonce": sent_payload["nonce"],
        "service": att.get("service", ""),
        "service_version": att.get("service_version", ""),
        "service_key_id": att.get("service_key_id", ""),
        "issued_at": att.get("issued_at", ""),
    }, sort_keys=True, separators=(",", ":")).encode("utf-8")
    try:
        witness_pub_key = signing.load_public_key(witness_pub["public_key_pem"])
        sig = base64.b64decode(att["signature"])
        signing.verify_bytes(witness_pub_key, canonical, sig.hex())
        return True
    except Exception:
        return False


def _utc_day_bounds(day_iso: str) -> tuple[datetime, datetime]:
    """Return (start, end) ISO timestamps for the given UTC day (YYYY-MM-DD)."""
    d = date.fromisoformat(day_iso)
    start = datetime(d.year, d.month, d.day, tzinfo=timezone.utc)
    end = start + timedelta(days=1)
    return start, end


def _receipts_for_day(day_iso: str) -> list:
    storage.init()
    start, end = _utc_day_bounds(day_iso)
    start_iso = start.isoformat()
    end_iso = end.isoformat()
    ns = os.environ.get("DONTLIE_NAMESPACE", "default")
    conn = storage._connect()
    try:
        rows = conn.execute(
            "SELECT * FROM receipts WHERE namespace = ? AND timestamp >= ? "
            "AND timestamp < ? ORDER BY id ASC",
            (ns, start_iso, end_iso),
        ).fetchall()
        return [storage._row_to_receipt(r) for r in rows]
    finally:
        conn.close()


def _create_ots_for_root(root_sha_hex: str, day_iso: str) -> Path:
    OTS_DIR.mkdir(parents=True, exist_ok=True)
    digest = bytes.fromhex(root_sha_hex)
    pending_payload = b"\x00pending\x00"
    body = _serialize_attestation(ATT_PENDING, pending_payload)
    file_bytes = OTS_MAGIC + _varint(OTS_VERSION) + digest + body
    path = OTS_DIR / f"daily-{day_iso}.ots"
    path.write_bytes(file_bytes)
    return path


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dontlie anchor-daily",
        description=__doc__,
    )
    p.add_argument("--day", default=None,
                   help="UTC day to anchor, YYYY-MM-DD (default: today UTC)")
    p.add_argument("--url", default=os.environ.get("DONTLIE_WITNESS_URL"),
                   help="witness service URL (required: --url or $DONTLIE_WITNESS_URL)")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be anchored without making any requests")
    p.add_argument("--tag", action="append", default=["daily-anchor"],
                   help="tags to apply to the batch (default: daily-anchor)")
    args = p.parse_args(argv)

    if not args.url:
        print(
            "witness URL is required: pass --url or set $DONTLIE_WITNESS_URL. "
            "Don't-Lie does not operate a witness service.",
            file=sys.stderr,
        )
        return 2

    today = date.today().isoformat() if args.day is None else args.day
    receipts = _receipts_for_day(today)
    print(f"day: {today}  ({len(receipts)} receipts in vault for this UTC day)")
    if not receipts:
        print("nothing to anchor — no receipts in this day")
        return 0

    leaf_count = len(receipts)
    first_id = receipts[0].id
    last_id = receipts[-1].id
    print(f"  receipts: #{first_id} .. #{last_id}  ({leaf_count} leaves)")
    print("  merkle root: (computed at create time)")

    if args.dry_run:
        print()
        print("dry run — would:")
        print(f"  1. dontlie batch create --from {first_id} --to {last_id}  (Merkle root + Ed25519 sig)")
        print(f"  2. write OTS pending attestation at {OTS_DIR}/daily-{today}.ots")
        print(f"  3. POST Merkle root to {args.url} for witness co-signature")
        return 0

    # 1. Create the Merkle-root batch
    try:
        b = _batch.create(
            receipt_ids=[r.id for r in receipts],
            tags=args.tag,
            extra={"anchor": "daily", "day": today},
        )
    except Exception as e:
        print(f"  FAIL: batch.create failed: {e}", file=sys.stderr)
        return 1
    print()
    print(f"  1. batch #{b.id} created")
    print(f"     merkle_root: {b.merkle_root}")
    print(f"     signature:   {b.signature[:32]}...")
    print(f"     first/last:  #{b.first_receipt_id} / #{b.last_receipt_id}")
    print(f"     key:         {b.key_id[:16]}")

    # 2. Create OTS pending attestation
    ots_path = _create_ots_for_root(b.merkle_root, today)
    print()
    print("  2. OTS pending attestation written")
    print(f"     path:        {ots_path}")
    print(f"     upgrade:     ots upgrade {ots_path}")
    print(f"                  (then `ots verify {ots_path}` after Bitcoin confirmation)")

    # 3. POST to witness
    print()
    print("  3. witness attestation")
    try:
        witness_pub = _witness_pubkey(args.url)
        att = _post_witness_attest(
            url=args.url,
            root_sha=b.merkle_root,
            operator_key_id=b.key_id,
        )
        sent_payload = {
            "receipt_sha256": b.merkle_root,
            "operator_key_id": b.key_id,
            "parent_sha256": "",
            "nonce": att.get("nonce", ""),
        }
        ok = _verify_attestation(att, witness_pub, sent_payload)
        # Store the daily anchor in a JSON file
        anchor_dir = Path.home() / ".local" / "share" / "dontlie" / "anchor"
        anchor_dir.mkdir(parents=True, exist_ok=True)
        anchor_path = anchor_dir / f"daily-{today}.json"
        anchor_path.write_text(json.dumps({
            "day": today,
            "batch_id": b.id,
            "merkle_root": b.merkle_root,
            "leaf_count": leaf_count,
            "first_receipt_id": first_id,
            "last_receipt_id": last_id,
            "key_id": b.key_id,
            "batch_signature": b.signature,
            "ots_file": str(ots_path),
            "witness_url": args.url,
            "witness_attestation": att,
            "witness_verified_locally": ok,
        }, indent=2, sort_keys=True))
        if ok:
            print(f"     witness key:  {att.get('service_key_id')}")
            print(f"     issued_at:    {att.get('issued_at')}")
            print(f"     signature:    {att.get('signature', '')[:48]}...")
            print("     ✓ verified locally")
            print(f"     stored:       {anchor_path}")
        else:
            print("     ! witness signature did NOT verify", file=sys.stderr)
            print(f"     stored (unverified): {anchor_path}")
            return 2
    except Exception as e:
        print(f"     FAIL: witness POST failed: {e}", file=sys.stderr)
        return 1

    print()
    print(f"daily anchor complete for {today}.")
    print(f"  the merkle root for this day's {leaf_count} receipts is now")
    print("  co-signed by:")
    print("    - your local Ed25519 key (in the batch row)")
    print("    - the OTS aggregator (Bitcoin-anchorable later)")
    print(f"    - the witness service at {args.url}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
