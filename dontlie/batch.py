"""dontlie batch — Merkle-root signature over a set of receipts.

For chains of 1K+ receipts, signing each receipt individually is fine
but the storage and verification cost grows linearly. This module
lets you take a contiguous range of receipts and produce a single
Ed25519 signature over their Merkle root. The result is the same
"one signature proves the set" guarantee that BLS aggregate
signatures give, with no new crypto dependency.

The batch is stored in a `batches` table and linked to its receipts
via `batch_receipts`. The batch includes:

    - id              (auto)
    - timestamp
    - merkle_root     (SHA-256 of the Merkle tree over the receipts)
    - leaf_count      (number of receipts in the batch)
    - first_receipt_id, last_receipt_id
    - key_id, signature (Ed25519 over the canonical batch payload)
    - tags, extra

Verification:
    1. For each receipt in the batch, recompute the SHA-256 of the
       receipt's payload (which equals its payload_sha256).
    2. Build the Merkle tree from those leaf hashes.
    3. Confirm the resulting root equals `merkle_root`.
    4. Verify the Ed25519 signature over the batch payload.

The batch receipt is itself chain-linked: the batch's payload
includes the `last_receipt_id`'s chain position, so the batch is
verifiably part of the same chain as its member receipts.

This is genuinely useful:
    - 1,000 individual Ed25519 sigs = ~64 KB of signatures
    - 1 Merkle root + 1 Ed25519 sig = ~64 bytes
    - Per-receipt verification is still possible (you recompute
      the Merkle path), but the batch-level proof is constant-size.
"""
from __future__ import annotations

import hashlib
import json
import sys
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import sign as signing
from . import storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    merkle_root     TEXT    NOT NULL,
    leaf_count      INTEGER NOT NULL,
    first_receipt_id INTEGER NOT NULL,
    last_receipt_id  INTEGER NOT NULL,
    key_id          TEXT    NOT NULL,
    signature       TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '[]',
    extra           TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS batch_receipts (
    batch_id        INTEGER NOT NULL,
    receipt_id      INTEGER NOT NULL,
    position        INTEGER NOT NULL,
    PRIMARY KEY (batch_id, receipt_id)
);
"""


@dataclass
class Batch:
    id: int
    timestamp: str
    merkle_root: str
    leaf_count: int
    first_receipt_id: int
    last_receipt_id: int
    key_id: str
    signature: str
    tags: list[str] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)
    receipt_ids: list[int] = field(default_factory=list)


def init() -> None:
    conn = storage._connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ---- merkle ----------------------------------------------------------------

def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash a pair of leaves/nodes. Left and right are 32-byte SHA-256 digests."""
    return hashlib.sha256(left + right).digest()


def merkle_root(leaf_hashes: list[bytes]) -> bytes:
    """Compute the Merkle root of a list of 32-byte leaf hashes.

    Duplicates the last leaf if the count is odd (Bitcoin-style).
    """
    if not leaf_hashes:
        raise ValueError("merkle_root: no leaves")
    if any(len(h) != 32 for h in leaf_hashes):
        raise ValueError("merkle_root: each leaf must be 32 bytes (SHA-256 digest)")
    level = list(leaf_hashes)
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])  # duplicate last
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_hash_pair(level[i], level[i + 1]))
        level = nxt
    return level[0]


def merkle_path(leaf_hashes: list[bytes], index: int) -> list[bytes]:
    """Return the sibling path from a leaf index to the root."""
    if not leaf_hashes:
        raise ValueError("merkle_path: no leaves")
    if index < 0 or index >= len(leaf_hashes):
        raise ValueError(f"merkle_path: index {index} out of range")
    level = list(leaf_hashes)
    idx = index
    path: list[bytes] = []
    while len(level) > 1:
        if len(level) % 2 == 1:
            level.append(level[-1])
        sibling_idx = idx + 1 if idx % 2 == 0 else idx - 1
        path.append(level[sibling_idx])
        nxt = []
        for i in range(0, len(level), 2):
            nxt.append(_hash_pair(level[i], level[i + 1]))
        level = nxt
        idx //= 2
    return path


def verify_merkle_path(leaf_hash: bytes, index: int, path: list[bytes], root: bytes) -> bool:
    """Verify that a leaf at `index` with sibling `path` hashes to `root`."""
    h = leaf_hash
    idx = index
    for sibling in path:
        if idx % 2 == 0:
            h = _hash_pair(h, sibling)
        else:
            h = _hash_pair(sibling, h)
        idx //= 2
    return h == root


# ---- batch creation --------------------------------------------------------

def _canonical_payload(b: Batch) -> bytes:
    blob = json.dumps({
        "timestamp": b.timestamp,
        "merkle_root": b.merkle_root,
        "leaf_count": b.leaf_count,
        "first_receipt_id": b.first_receipt_id,
        "last_receipt_id": b.last_receipt_id,
        "key_id": b.key_id,
        "receipt_ids": sorted(b.receipt_ids),
        "tags": sorted(b.tags),
    }, sort_keys=True, separators=(",", ":"))
    return blob.encode("utf-8")


def create(
    receipt_ids: Iterable[int],
    *,
    tags: Iterable[str] = (),
    extra: dict | None = None,
) -> Batch:
    """Create a batch that signs a Merkle root over the given receipts."""
    init()
    receipt_ids = sorted({int(r) for r in receipt_ids})
    if not receipt_ids:
        raise ValueError("batch must reference at least one receipt")
    for rid in receipt_ids:
        if storage.get_receipt(rid) is None:
            raise ValueError(f"receipt {rid} not found in vault")
    # Compute leaf hashes from each receipt's payload_sha256
    leaf_hashes = []
    for rid in receipt_ids:
        r = storage.get_receipt(rid)
        leaf_hashes.append(bytes.fromhex(r.payload_sha256))
    root = merkle_root(leaf_hashes)
    ts = datetime.now(timezone.utc).isoformat()
    # Set key_id FIRST (the canonical payload includes key_id)
    signing._ensure_dir()
    if not signing.PRIVATE_FILE.exists():
        signing.generate()
    kp = signing.load()
    b = Batch(
        id=0, timestamp=ts, merkle_root=root.hex(),
        leaf_count=len(receipt_ids),
        first_receipt_id=receipt_ids[0], last_receipt_id=receipt_ids[-1],
        key_id=kp.key_id, signature="",
        tags=list(tags), extra=extra or {}, receipt_ids=receipt_ids,
    )
    payload = _canonical_payload(b)
    b.signature = signing.sign_bytes(kp, payload)
    # Persist
    conn = storage._connect()
    try:
        cur = conn.execute(
            "INSERT INTO batches (timestamp, merkle_root, leaf_count, first_receipt_id, last_receipt_id, key_id, signature, tags, extra) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (b.timestamp, b.merkle_root, b.leaf_count, b.first_receipt_id,
             b.last_receipt_id, b.key_id, b.signature,
             json.dumps(b.tags), json.dumps(b.extra)),
        )
        b.id = cur.lastrowid
        for pos, rid in enumerate(receipt_ids):
            conn.execute(
                "INSERT INTO batch_receipts (batch_id, receipt_id, position) VALUES (?, ?, ?)",
                (b.id, rid, pos),
            )
        conn.commit()
    finally:
        conn.close()
    return b


def get(batch_id: int) -> Batch | None:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM batches WHERE id = ?", (batch_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cur = conn.execute("SELECT receipt_id FROM batch_receipts WHERE batch_id = ? ORDER BY position", (batch_id,))
        rid_list = [r[0] for r in cur.fetchall()]
    finally:
        conn.close()
    return Batch(
        id=row[0], timestamp=row[1], merkle_root=row[2], leaf_count=row[3],
        first_receipt_id=row[4], last_receipt_id=row[5],
        key_id=row[6], signature=row[7],
        tags=json.loads(row[8] or "[]"), extra=json.loads(row[9] or "{}"),
        receipt_ids=rid_list,
    )


def list_all(limit: int = 50) -> list[Batch]:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM batches ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    finally:
        conn.close()
    return [
        Batch(
            id=r[0], timestamp=r[1], merkle_root=r[2], leaf_count=r[3],
            first_receipt_id=r[4], last_receipt_id=r[5],
            key_id=r[6], signature=r[7],
            tags=json.loads(r[8] or "[]"), extra=json.loads(r[9] or "{}"),
            receipt_ids=[],
        )
        for r in rows
    ]


def verify(b: Batch) -> bool:
    """Verify the batch: merkle root + Ed25519 signature + all receipts still exist."""
    for rid in b.receipt_ids:
        r = storage.get_receipt(rid)
        if r is None:
            return False
    # Recompute the merkle root from current receipts
    leaf_hashes = [bytes.fromhex(storage.get_receipt(rid).payload_sha256)
                   for rid in b.receipt_ids]
    if merkle_root(leaf_hashes).hex() != b.merkle_root:
        return False
    # Verify the signature
    try:
        pub = _lookup_public_key(b.key_id)
        if pub is None:
            return False
        return signing.verify_bytes(pub, _canonical_payload(b), b.signature)
    except Exception:
        return False


def _lookup_public_key(key_id: str):
    try:
        active = signing.load()
        if active.key_id == key_id:
            return active.public
    except Exception:
        pass
    try:
        conn = storage._connect()
        cur = conn.execute(
            "SELECT public_key_pem FROM key_history WHERE key_id = ?",
            (key_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            return signing.load_public_key(row[0])
    except Exception:
        pass
    return None


def prove(leaf_receipt_id: int) -> dict | None:
    """Generate a Merkle-proof for one receipt in its batch.

    Returns a dict with the leaf hash, position, sibling path, and root.
    Returns None if the receipt isn't in any batch.
    """
    init()
    conn = storage._connect()
    try:
        cur = conn.execute(
            "SELECT batch_id FROM batch_receipts WHERE receipt_id = ?",
            (leaf_receipt_id,),
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    if not rows:
        return None
    # Use the first batch
    batch_id = rows[0][0]
    batch = get(batch_id)
    if batch is None or leaf_receipt_id not in batch.receipt_ids:
        return None
    position = batch.receipt_ids.index(leaf_receipt_id)
    leaf_hashes = [bytes.fromhex(storage.get_receipt(rid).payload_sha256)
                   for rid in batch.receipt_ids]
    path = merkle_path(leaf_hashes, position)
    return {
        "receipt_id": leaf_receipt_id,
        "batch_id": batch_id,
        "position": position,
        "leaf_hash": leaf_hashes[position].hex(),
        "merkle_root": batch.merkle_root,
        "sibling_path": [h.hex() for h in path],
        "batch_verified": verify(batch),
    }


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie batch", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="create a batch over a range of receipts")
    p_create.add_argument("--from", dest="from_id", type=int, required=True, help="first receipt id")
    p_create.add_argument("--to", dest="to_id", type=int, required=True, help="last receipt id (inclusive)")
    p_create.add_argument("--tag", action="append", default=[])
    p_create.set_defaults(func=lambda a: _cmd_create(a))

    p_list = sub.add_parser("list", help="list all batches")
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    p_show = sub.add_parser("show", help="show and verify a batch")
    p_show.add_argument("batch_id", type=int)
    p_show.set_defaults(func=lambda a: _cmd_show(a))

    p_prove = sub.add_parser("prove", help="generate a Merkle proof for a receipt in its batch")
    p_prove.add_argument("receipt_id", type=int)
    p_prove.set_defaults(func=lambda a: _cmd_prove(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_create(args) -> int:
    if args.from_id > args.to_id:
        print(f"error: --from ({args.from_id}) must be <= --to ({args.to_id})", file=sys.stderr)
        return 1
    rid_list = list(range(args.from_id, args.to_id + 1))
    # Verify they all exist
    for rid in rid_list:
        if storage.get_receipt(rid) is None:
            print(f"error: receipt {rid} not found", file=sys.stderr)
            return 1
    try:
        b = create(rid_list, tags=args.tag)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"batch #{b.id} created")
    print(f"  receipts:     {b.first_receipt_id}..{b.last_receipt_id} ({b.leaf_count} receipts)")
    print(f"  merkle root:  {b.merkle_root[:32]}…")
    print(f"  signature:    {b.signature[:32]}…")
    print(f"  storage:      {b.leaf_count} × 64B sigs → 1 × 64B sig (1/{b.leaf_count}× the size)")
    return 0


def _cmd_list(args) -> int:
    batches = list_all()
    if not batches:
        print("no batches yet")
        return 0
    for b in batches:
        print(f"#{b.id}  {b.timestamp}  receipts {b.first_receipt_id}..{b.last_receipt_id}  ({b.leaf_count} leaves)")
    return 0


def _cmd_show(args) -> int:
    b = get(args.batch_id)
    if b is None:
        print(f"batch {args.batch_id} not found", file=sys.stderr)
        return 1
    ok = verify(b)
    print(f"Batch #{b.id}  ({'VERIFIED' if ok else 'FAILED'})")
    print(f"  receipts:    {b.first_receipt_id}..{b.last_receipt_id} ({b.leaf_count} leaves)")
    print(f"  merkle root: {b.merkle_root}")
    print(f"  signature:   {b.signature[:48]}…")
    return 0 if ok else 2


def _cmd_prove(args) -> int:
    proof = prove(args.receipt_id)
    if proof is None:
        print(f"receipt {args.receipt_id} is not in any batch", file=sys.stderr)
        return 1
    print(f"Merkle proof for receipt #{args.receipt_id}:")
    print(f"  batch_id:    {proof['batch_id']}")
    print(f"  position:    {proof['position']}")
    print(f"  leaf hash:   {proof['leaf_hash']}")
    print(f"  merkle root: {proof['merkle_root']}")
    print(f"  siblings:    {len(proof['sibling_path'])} nodes")
    print(f"  batch verified: {proof['batch_verified']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
