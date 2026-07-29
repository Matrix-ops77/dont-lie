"""dontlie witness-coverage — co-sign every receipt in the local vault
with the hosted witness notary.

Iterates all receipts in the current namespace, posts each one's
payload_sha256 to the witness /attest endpoint, locally verifies the
returned signature, and stores the attestation under
~/.local/share/dontlie/witness/attestations/{receipt_id}.json.

Closes Reasonable Doubt #5 at scale: the entire chain's existence is
co-signed by a third party whose key the operator doesn't hold. This
is what makes "the chain did not break" a third-party-witnessed claim,
not just an operator claim.

Usage:
    dontlie witness-coverage                    # all receipts in current namespace
    dontlie witness-coverage --limit 100        # most recent 100 only
    dontlie witness-coverage --since 2026-07-01 # receipts since date
    dontlie witness-coverage --resume           # skip already-attested
    dontlie witness-coverage --dry-run          # show what would be attested
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
from datetime import datetime, timezone
from pathlib import Path

from . import __version__, sign as signing, storage
from .offline import require_network


ATT_DIR = Path(
    os.environ.get(
        "DONTLIE_WITNESS_ATT_DIR",
        str(Path.home() / ".local" / "share" / "dontlie" / "witness" / "attestations"),
    )
)

# Schema fragment for the `witness_attestations` table that `trust.py` reads
# from. Created lazily on first run; do not migrate down.
_WITNESS_TABLE_DDL = """
CREATE TABLE IF NOT EXISTS witness_attestations (
    receipt_id     INTEGER NOT NULL,
    witness_url    TEXT    NOT NULL,
    witness_key_id TEXT    NOT NULL,
    receipt_sha256 TEXT    NOT NULL,
    parent_sha256  TEXT,
    issued_at      TEXT    NOT NULL,
    nonce          TEXT    NOT NULL,
    signature      TEXT    NOT NULL,
    verified_locally INTEGER NOT NULL DEFAULT 0,
    fetched_at     TEXT    NOT NULL,
    PRIMARY KEY (receipt_id, witness_url)
);
"""


def _ensure_witness_table(conn) -> None:
    conn.executescript(_WITNESS_TABLE_DDL)
    conn.commit()


def _record_witness_attestation(
    conn,
    receipt_id: int,
    witness_url: str,
    att: dict,
    verified_locally: bool,
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO witness_attestations
            (receipt_id, witness_url, witness_key_id, receipt_sha256,
             parent_sha256, issued_at, nonce, signature, verified_locally,
             fetched_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            receipt_id,
            witness_url,
            att.get("service_key_id", ""),
            att.get("receipt_sha256", ""),
            att.get("parent_sha256"),
            att.get("issued_at", ""),
            att.get("nonce", ""),
            att.get("signature", ""),
            1 if verified_locally else 0,
            datetime.now(timezone.utc).isoformat(),
        ),
    )


def _witness_pubkey(url: str, timeout: int = 10) -> dict:
    pkreq = urllib.request.Request(
        url.rstrip("/") + "/pubkey", method="GET",
        headers={"User-Agent": f"dontlie-cli/{__version__} (+https://dontlie.pages.dev)"},
    )
    with urllib.request.urlopen(pkreq, timeout=timeout) as resp:
        return json.loads(resp.read())


def _attest_one(
    url: str,
    receipt_sha: str,
    operator_key_id: str,
    parent_sha: str | None,
    nonce: str | None = None,
) -> dict:
    """POST one receipt hash to the witness. Returns the parsed JSON attestation."""
    nonce = nonce or secrets.token_hex(16)
    payload = {
        "receipt_sha256": receipt_sha,
        "operator_key_id": operator_key_id,
        "nonce": nonce,
    }
    if parent_sha:
        payload["parent_sha256"] = parent_sha
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
    """Locally verify the witness signature against the canonical message."""
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
        # verify_bytes expects hex signature; convert bytes to hex
        signing.verify_bytes(witness_pub_key, canonical, sig.hex())
        return True
    except Exception:
        return False


def _save_attestation(receipt_id: int, att: dict, witness_url: str) -> Path:
    ATT_DIR.mkdir(parents=True, exist_ok=True)
    path = ATT_DIR / f"receipt-{receipt_id}.json"
    payload = {
        "receipt_id": receipt_id,
        "witness_url": witness_url,
        "attestation": att,
    }
    path.write_text(json.dumps(payload, indent=2, sort_keys=True))
    return path


def _already_attested(receipt_id: int) -> bool:
    return (ATT_DIR / f"receipt-{receipt_id}.json").exists()


def _backfill_db_from_json(conn, receipt_id: int, witness_url: str) -> None:
    """If a JSON attestation exists but the DB has no row, copy it in.

    This makes `dontlie witness-coverage --resume` safe to run on a
    vault where earlier attestations were stored before the
    `witness_attestations` table existed.
    """
    cur = conn.execute(
        "SELECT 1 FROM witness_attestations WHERE receipt_id = ? AND witness_url = ?",
        (receipt_id, witness_url),
    )
    if cur.fetchone() is not None:
        return
    path = ATT_DIR / f"receipt-{receipt_id}.json"
    if not path.exists():
        return
    try:
        wrapper = json.loads(path.read_text())
    except Exception:
        return
    att = wrapper.get("attestation", {})
    if not att:
        return
    _record_witness_attestation(
        conn, receipt_id, witness_url, att, verified_locally=True
    )
    conn.commit()


def coverage_iter(
    *,
    limit: int | None = None,
    since: str | None = None,
    resume: bool = False,
    dry_run: bool = False,
    url: str = "https://dontlie-witness.buxmont-floodassist.workers.dev",
    on_progress=None,
) -> tuple[int, int, int, list[str]]:
    """Iterate all matching receipts and co-sign each with the witness.

    Returns (ok, skipped, failed, failed_ids).
    """
    # PLDG.md: opt-in commands must refuse to make network calls when
    # DONTLIE_OFFLINE=1 is set.
    require_network("witness-coverage")
    storage.init()
    if dry_run:
        # Fetch without attesting
        receipts = storage.list_receipts(limit=limit or 10000, offset=0)
        if since:
            receipts = [r for r in receipts if r.timestamp >= since]
        print(f"dry run: would co-sign {len(receipts)} receipt(s) with {url}")
        for r in receipts[:10]:
            print(f"  - receipt #{r.id}  sha={r.payload_sha256[:16]}  key={r.key_id[:8]}  ts={r.timestamp}")
        if len(receipts) > 10:
            print(f"  ... and {len(receipts) - 10} more")
        return len(receipts), 0, 0, []

    receipts = storage.list_receipts(limit=limit or 10000, offset=0)
    if since:
        receipts = [r for r in receipts if r.timestamp >= since]

    # Resolve witness public key once (avoids per-receipt fetch)
    try:
        witness_pub = _witness_pubkey(url)
    except Exception as e:
        print(f"could not fetch witness pubkey from {url}: {e}", file=sys.stderr)
        return 0, 0, len(receipts), [str(r.id) for r in receipts]

    ok = skipped = failed = 0
    failed_ids: list[str] = []
    total = len(receipts)
    conn = storage._connect()
    try:
        _ensure_witness_table(conn)
        for idx, r in enumerate(receipts, start=1):
            if resume and _already_attested(r.id):
                # Make sure the DB also has a row (the JSON may have been
                # written before the DB column was added).
                _backfill_db_from_json(conn, r.id, url)
                skipped += 1
                if on_progress:
                    on_progress(idx, total, r.id, "skipped")
                continue
            try:
                parent_sha = None
                if r.extra:
                    parent_sha = r.extra.get("_dontlie_parent_sha256")
                att = _attest_one(
                    url=url,
                    receipt_sha=r.payload_sha256,
                    operator_key_id=r.key_id,
                    parent_sha=parent_sha,
                )
                # Re-verify locally
                sent_payload = {
                    "receipt_sha256": r.payload_sha256,
                    "operator_key_id": r.key_id,
                    "parent_sha256": parent_sha or "",
                    "nonce": att.get("nonce", ""),
                }
                verified = _verify_attestation(att, witness_pub, sent_payload)
                if not verified:
                    failed += 1
                    failed_ids.append(str(r.id))
                    if on_progress:
                        on_progress(idx, total, r.id, "FAIL-verify")
                    continue
                _save_attestation(r.id, att, url)
                _record_witness_attestation(conn, r.id, url, att, verified_locally=True)
                conn.commit()
                ok += 1
                if on_progress:
                    on_progress(idx, total, r.id, "ok")
            except Exception as e:
                failed += 1
                failed_ids.append(str(r.id))
                if on_progress:
                    on_progress(idx, total, r.id, f"FAIL: {e}")
    finally:
        conn.close()
    return ok, skipped, failed, failed_ids


def _print_progress(idx: int, total: int, rid: int, status: str) -> None:
    if idx % 10 == 0 or status != "ok":
        print(f"  [{idx:4d}/{total}]  receipt #{rid}  {status}", file=sys.stderr)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dontlie witness-coverage",
        description="Co-sign every receipt in the current namespace with the witness.",
    )
    p.add_argument("--url", default=os.environ.get(
        "DONTLIE_WITNESS_URL",
        "https://dontlie-witness.buxmont-floodassist.workers.dev",
    ), help="witness service URL (default: hosted dontlie witness)")
    p.add_argument("--limit", type=int, default=None,
                   help="max number of receipts to attest (default: all)")
    p.add_argument("--since", default=None,
                   help="ISO date or timestamp; skip receipts older than this")
    p.add_argument("--resume", action="store_true",
                   help="skip receipts that already have a stored attestation")
    p.add_argument("--dry-run", action="store_true",
                   help="show what would be attested without making any requests")
    p.add_argument("--quiet", action="store_true",
                   help="suppress per-receipt progress output")
    args = p.parse_args(argv)

    # PLDG.md: refuse to make a network call if DONTLIE_OFFLINE=1
    from .offline import OfflineRefused
    try:
        require_network("witness-coverage")
    except OfflineRefused as exc:
        print(f"witness-coverage: {exc}", file=sys.stderr)
        return 2  # distinct exit code so callers can detect refusal

    def _progress(idx, total, rid, status):
        if not args.quiet:
            _print_progress(idx, total, rid, status)

    ok, skipped, failed, failed_ids = coverage_iter(
        limit=args.limit,
        since=args.since,
        resume=args.resume,
        dry_run=args.dry_run,
        url=args.url,
        on_progress=_progress,
    )

    print(f"witness coverage complete: {ok} ok, {skipped} skipped, {failed} failed")
    if failed_ids:
        print(f"  failed receipt ids: {', '.join(failed_ids[:20])}", file=sys.stderr)
        if len(failed_ids) > 20:
            print(f"  ... and {len(failed_ids) - 20} more", file=sys.stderr)
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
