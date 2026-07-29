"""dontlie annotate — attach a signed reviewer note to a receipt.

An annotation is a separate signed object that points at one or more
receipts. Use case: a compliance officer reviews receipt #1024 and
attaches the note "verified by GC, no action needed" signed under
their own key. The annotation is itself part of the audit chain.

Annotations are stored in an `annotations` table:
    id, timestamp, actor, note, sha256, key_id, signature, tags, extra

A many-to-many `annotation_receipts` table links annotations to one
or more receipt_ids. This lets a single annotation cover a group of
related receipts (e.g., "all 47 calls in the May 12 fraud-review batch
were confirmed compliant").
"""
from __future__ import annotations

import json
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import sign as signing
from . import storage


SCHEMA = """
CREATE TABLE IF NOT EXISTS annotations (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    actor           TEXT    NOT NULL,
    note            TEXT    NOT NULL,
    annotation_sha  TEXT    NOT NULL,
    key_id          TEXT    NOT NULL,
    signature       TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '[]',
    extra           TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS annotation_receipts (
    annotation_id   INTEGER NOT NULL,
    receipt_id      INTEGER NOT NULL,
    PRIMARY KEY (annotation_id, receipt_id)
);
"""


@dataclass
class Annotation:
    id: int
    timestamp: str
    actor: str
    note: str
    annotation_sha: str
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


def _canonical_payload(a: Annotation) -> bytes:
    # NB: do NOT include `id` — see comment in decision.py for the same fix.
    blob = json.dumps({
        "timestamp": a.timestamp,
        "actor": a.actor,
        "note": a.note,
        "annotation_sha": a.annotation_sha,
        "key_id": a.key_id,
        "receipt_ids": sorted(a.receipt_ids),
        "tags": sorted(a.tags),
    }, sort_keys=True, separators=(",", ":"))
    return blob.encode("utf-8")


def create(
    actor: str,
    note: str,
    receipt_ids: Iterable[int],
    *,
    tags: Iterable[str] = (),
    extra: dict | None = None,
) -> Annotation:
    """Create a new annotation that points at one or more receipts."""
    init()
    receipt_ids = sorted(set(int(r) for r in receipt_ids))
    if not receipt_ids:
        raise ValueError("annotation must reference at least one receipt")
    for rid in receipt_ids:
        if storage.get_receipt(rid) is None:
            raise ValueError(f"receipt {rid} not found in vault")
    import hashlib
    ts = datetime.now(timezone.utc).isoformat()
    # Set key_id FIRST (see decision.py for the same fix)
    signing._ensure_dir()
    if not signing.PRIVATE_FILE.exists():
        signing.generate()
    kp = signing.load()
    a = Annotation(
        id=0, timestamp=ts, actor=actor, note=note,
        annotation_sha="", key_id=kp.key_id, signature="",
        tags=list(tags), extra=extra or {}, receipt_ids=receipt_ids,
    )
    payload = _canonical_payload(a)
    annotation_sha = hashlib.sha256(payload).hexdigest()
    a.annotation_sha = annotation_sha
    # Re-hash with the annotation_sha filled in
    payload = _canonical_payload(a)
    a.signature = signing.sign_bytes(kp, payload)
    conn = storage._connect()
    try:
        cur = conn.execute(
            "INSERT INTO annotations (timestamp, actor, note, annotation_sha, key_id, signature, tags, extra) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (a.timestamp, a.actor, a.note, a.annotation_sha, a.key_id, a.signature,
             json.dumps(a.tags), json.dumps(a.extra)),
        )
        a.id = cur.lastrowid
        for rid in a.receipt_ids:
            conn.execute(
                "INSERT OR IGNORE INTO annotation_receipts (annotation_id, receipt_id) VALUES (?, ?)",
                (a.id, rid),
            )
        conn.commit()
    finally:
        conn.close()
    return a


def get(annotation_id: int) -> Annotation | None:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM annotations WHERE id = ?", (annotation_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cur = conn.execute("SELECT receipt_id FROM annotation_receipts WHERE annotation_id = ? ORDER BY receipt_id", (annotation_id,))
        rid_list = [r[0] for r in cur.fetchall()]
    finally:
        conn.close()
    return Annotation(
        id=row[0], timestamp=row[1], actor=row[2], note=row[3],
        annotation_sha=row[4], key_id=row[5], signature=row[6],
        tags=json.loads(row[7] or "[]"), extra=json.loads(row[8] or "{}"),
        receipt_ids=rid_list,
    )


def list_for_receipt(receipt_id: int) -> list[Annotation]:
    """List all annotations that point at a given receipt."""
    init()
    conn = storage._connect()
    try:
        cur = conn.execute(
            "SELECT annotation_id FROM annotation_receipts WHERE receipt_id = ? ORDER BY annotation_id",
            (receipt_id,),
        )
        ids = [r[0] for r in cur.fetchall()]
    finally:
        conn.close()
    out = []
    for aid in ids:
        a = get(aid)
        if a is not None:
            out.append(a)
    return out


def verify(a: Annotation) -> bool:
    for rid in a.receipt_ids:
        if storage.get_receipt(rid) is None:
            return False
    payload = _canonical_payload(a)
    try:
        # Look up the public key for this key_id
        pub = _lookup_public_key(a.key_id)
        if pub is None:
            return False
        return signing.verify_bytes(pub, payload, a.signature)
    except Exception:
        return False


def _lookup_public_key(key_id: str):
    import sqlite3
    from . import sign as signing_mod
    try:
        active = signing_mod.load()
        if active.key_id == key_id:
            return active.public
    except Exception:
        pass
    try:
        conn = sqlite3.connect(str(storage.DB_PATH))
        cur = conn.execute(
            "SELECT public_key_pem FROM key_history WHERE key_id = ?",
            (key_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row and row[0]:
            return signing_mod.load_public_key(row[0])
    except Exception:
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie annotate", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_add = sub.add_parser("add", help="attach a signed note to one or more receipts")
    p_add.add_argument("--actor", required=True, help="who is adding the note (e.g. 'gc@firm.com')")
    p_add.add_argument("--note", required=True, help="the note text")
    p_add.add_argument("--tag", action="append", default=[], help="add a tag (repeatable)")
    p_add.add_argument("receipt_ids", nargs="+", type=int, help="receipt IDs to annotate")
    p_add.set_defaults(func=lambda a: _cmd_add(a))

    p_show = sub.add_parser("show", help="show an annotation")
    p_show.add_argument("annotation_id", type=int)
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=lambda a: _cmd_show(a))

    p_list = sub.add_parser("list", help="list annotations on a receipt")
    p_list.add_argument("receipt_id", type=int)
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_add(args) -> int:
    try:
        a = create(
            actor=args.actor, note=args.note, receipt_ids=args.receipt_ids,
            tags=args.tag,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"annotation #{a.id} created")
    print(f"  actor:      {a.actor}")
    print(f"  timestamp:  {a.timestamp}")
    print(f"  receipts:   {', '.join('#' + str(r) for r in a.receipt_ids)}")
    print(f"  sha256:     {a.annotation_sha[:32]}…")
    print(f"  signature:  {a.signature[:32]}…")
    return 0


def _cmd_show(args) -> int:
    a = get(args.annotation_id)
    if a is None:
        print(f"annotation {args.annotation_id} not found", file=sys.stderr)
        return 1
    ok = verify(a)
    if args.json:
        print(json.dumps({"annotation": a.__dict__, "verified": ok}, indent=2, sort_keys=True, default=str))
    else:
        print(f"Annotation #{a.id}  ({'VERIFIED' if ok else 'FAILED'})")
        print(f"  actor:      {a.actor}")
        print(f"  timestamp:  {a.timestamp}")
        print(f"  note:       {a.note}")
        print(f"  receipts:   {', '.join('#' + str(r) for r in a.receipt_ids)}")
        print(f"  sha256:     {a.annotation_sha}")
        print(f"  signature:  {a.signature[:48]}…")
    return 0 if ok else 2


def _cmd_list(args) -> int:
    annotations = list_for_receipt(args.receipt_id)
    if not annotations:
        print(f"no annotations on receipt #{args.receipt_id}")
        return 0
    for a in annotations:
        print(f"#{a.id}  {a.timestamp}  [{a.actor}]  {a.note[:80]}{'…' if len(a.note) > 80 else ''}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
