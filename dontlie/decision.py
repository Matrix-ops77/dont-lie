"""dontlie decision — wrap multiple receipts into a signed "decision".

A "decision" is a higher-level unit of evidence than a single receipt. It says:
"I made this decision on this date, and the evidence supporting it is the
following set of receipts, each independently signed."

Use case: an AI-assisted credit decision needs to point at receipts
#1024, #1025, #1026 (the request, the response, the model explainability
call). A single receipt is the wrong unit; a bundle of receipts is the
right unit. The decision binds them together with its own signature.

Decisions are stored in a separate table `decisions` and linked to
receipts via a many-to-many `decision_receipts` table.
"""
from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import sign as signing
from . import storage

SCHEMA = """
CREATE TABLE IF NOT EXISTS decisions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    name            TEXT    NOT NULL,
    actor           TEXT    NOT NULL,
    notes           TEXT    NOT NULL DEFAULT '',
    decision_sha256 TEXT    NOT NULL,
    key_id          TEXT    NOT NULL,
    signature       TEXT    NOT NULL,
    tags            TEXT    NOT NULL DEFAULT '[]',
    extra           TEXT    NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS decision_receipts (
    decision_id     INTEGER NOT NULL,
    receipt_id      INTEGER NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'evidence',
    PRIMARY KEY (decision_id, receipt_id)
);
"""


@dataclass
class Decision:
    id: int
    timestamp: str
    name: str
    actor: str
    notes: str
    decision_sha256: str
    key_id: str
    signature: str
    tags: list[str] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)
    receipt_ids: list[int] = field(default_factory=list)


def init() -> None:
    """Ensure the decisions tables exist."""
    conn = storage._connect()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def _canonical_payload(d: Decision) -> bytes:
    # NB: do NOT include `id` — it is assigned by the database after the
    # payload is hashed and signed. Including it would make the hash
    # computed at create time non-deterministic with respect to the
    # hash recomputed at verify time.
    blob = json.dumps({
        "timestamp": d.timestamp,
        "name": d.name,
        "actor": d.actor,
        "notes": d.notes,
        "decision_sha256": d.decision_sha256,
        "key_id": d.key_id,
        "receipt_ids": sorted(d.receipt_ids),
        "tags": sorted(d.tags),
    }, sort_keys=True, separators=(",", ":"))
    return blob.encode("utf-8")


def create(
    name: str,
    actor: str,
    receipt_ids: Iterable[int],
    *,
    notes: str = "",
    tags: Iterable[str] = (),
    extra: dict | None = None,
) -> Decision:
    """Create a new decision that binds a set of receipts together."""
    init()
    receipt_ids = sorted({int(r) for r in receipt_ids})
    if not receipt_ids:
        raise ValueError("decision must reference at least one receipt")
    # Confirm the receipts exist
    for rid in receipt_ids:
        if storage.get_receipt(rid) is None:
            raise ValueError(f"receipt {rid} not found in vault")
    # Build the canonical payload
    import hashlib
    ts = datetime.now(timezone.utc).isoformat()
    # Build the Decision. NB: the key_id must be set BEFORE the payload is
    # hashed, because key_id is part of the canonical payload and the
    # signature is over the same payload.
    signing._ensure_dir()
    if not signing.PRIVATE_FILE.exists():
        signing.generate()
    kp = signing.load()
    d = Decision(
        id=0, timestamp=ts, name=name, actor=actor, notes=notes,
        decision_sha256="", key_id=kp.key_id, signature="",
        tags=list(tags), extra=extra or {}, receipt_ids=receipt_ids,
    )
    # Hash the payload (key_id is set, decision_sha256 is empty for the
    # first pass; we hash once and store)
    payload = _canonical_payload(d)
    decision_sha = hashlib.sha256(payload).hexdigest()
    d.decision_sha256 = decision_sha
    # Re-hash with the decision_sha256 filled in (the canonical payload
    # includes decision_sha256 itself)
    payload = _canonical_payload(d)
    d.signature = signing.sign_bytes(kp, payload)
    # Persist
    conn = storage._connect()
    try:
        cur = conn.execute(
            "INSERT INTO decisions (timestamp, name, actor, notes, decision_sha256, key_id, signature, tags, extra) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (d.timestamp, d.name, d.actor, d.notes, d.decision_sha256,
             d.key_id, d.signature, json.dumps(d.tags), json.dumps(d.extra)),
        )
        d.id = cur.lastrowid
        for rid in d.receipt_ids:
            conn.execute(
                "INSERT OR IGNORE INTO decision_receipts (decision_id, receipt_id, role) VALUES (?, ?, ?)",
                (d.id, rid, "evidence"),
            )
        conn.commit()
    finally:
        conn.close()
    return d


def get(decision_id: int) -> Decision | None:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM decisions WHERE id = ?", (decision_id,))
        row = cur.fetchone()
        if row is None:
            return None
        cur = conn.execute("SELECT receipt_id FROM decision_receipts WHERE decision_id = ? ORDER BY receipt_id", (decision_id,))
        rid_list = [r[0] for r in cur.fetchall()]
    finally:
        conn.close()
    return Decision(
        id=row[0], timestamp=row[1], name=row[2], actor=row[3], notes=row[4],
        decision_sha256=row[5], key_id=row[6], signature=row[7],
        tags=json.loads(row[8] or "[]"), extra=json.loads(row[9] or "{}"),
        receipt_ids=rid_list,
    )


def list_all(limit: int = 50) -> list[Decision]:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM decisions ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    finally:
        conn.close()
    return [
        Decision(
            id=r[0], timestamp=r[1], name=r[2], actor=r[3], notes=r[4],
            decision_sha256=r[5], key_id=r[6], signature=r[7],
            tags=json.loads(r[8] or "[]"), extra=json.loads(r[9] or "{}"),
            receipt_ids=[],  # not populated for list; call get() to populate
        )
        for r in rows
    ]


def verify(d: Decision) -> bool:
    """Verify the decision's signature and the integrity of its receipt set."""
    # Check that all linked receipts are still in the vault
    for rid in d.receipt_ids:
        if storage.get_receipt(rid) is None:
            return False
    # Check that the signature is over the right hash
    payload = _canonical_payload(d)
    try:
        # Look up the public key for this key_id (active or historical)
        pub = _lookup_public_key(d.key_id)
        if pub is None:
            return False
        return signing.verify_bytes(pub, payload, d.signature)
    except Exception:
        return False


def _lookup_public_key(key_id: str):
    """Look up a public key by key_id in the active key or in key_history."""
    from . import sign as signing_mod
    # First: the active key
    try:
        active = signing_mod.load()
        if active.key_id == key_id:
            return active.public
    except Exception:
        pass
    # Fall back: key_history table
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
    parser = argparse.ArgumentParser(prog="dontlie decision", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="create a decision that binds a set of receipts")
    p_create.add_argument("--name", required=True, help="human-readable name (e.g. 'approved loan 12345')")
    p_create.add_argument("--actor", required=True, help="who/what made the decision (e.g. 'ai-agent:v2' or 'jane@firm.com')")
    p_create.add_argument("--notes", default="", help="free-text notes")
    p_create.add_argument("--tag", action="append", default=[], help="add a tag (repeatable)")
    p_create.add_argument("receipt_ids", nargs="+", type=int, help="receipt IDs to bind into the decision")
    p_create.set_defaults(func=lambda a: _cmd_create(a))

    p_list = sub.add_parser("list", help="list all decisions")
    p_list.add_argument("--limit", type=int, default=20)
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    p_show = sub.add_parser("show", help="show a decision and verify it")
    p_show.add_argument("decision_id", type=int)
    p_show.add_argument("--json", action="store_true")
    p_show.set_defaults(func=lambda a: _cmd_show(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_create(args) -> int:
    try:
        d = create(
            name=args.name, actor=args.actor, receipt_ids=args.receipt_ids,
            notes=args.notes, tags=args.tag,
        )
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"decision #{d.id} created")
    print(f"  name:        {d.name}")
    print(f"  actor:       {d.actor}")
    print(f"  timestamp:   {d.timestamp}")
    print(f"  receipts:    {', '.join('#' + str(r) for r in d.receipt_ids)}")
    print(f"  sha256:      {d.decision_sha256[:32]}…")
    print(f"  signature:   {d.signature[:32]}…")
    return 0


def _cmd_list(args) -> int:
    decisions = list_all(limit=args.limit)
    if not decisions:
        print("no decisions yet")
        return 0
    for d in decisions:
        print(f"#{d.id}  {d.timestamp}  [{d.actor}]  {d.name}")
    return 0


def _cmd_show(args) -> int:
    import sys
    d = get(args.decision_id)
    if d is None:
        print(f"decision {args.decision_id} not found", file=sys.stderr)
        return 1
    ok = verify(d)
    if args.json:
        print(json.dumps({"decision": d.__dict__, "verified": ok}, indent=2, sort_keys=True, default=str))
    else:
        print(f"Decision #{d.id}  ({'VERIFIED' if ok else 'FAILED VERIFICATION'})")
        print(f"  name:       {d.name}")
        print(f"  actor:      {d.actor}")
        print(f"  timestamp:  {d.timestamp}")
        print(f"  notes:      {d.notes or '(none)'}")
        print(f"  receipts:   {', '.join('#' + str(r) for r in d.receipt_ids)}")
        print(f"  sha256:     {d.decision_sha256}")
        print(f"  signature:  {d.signature[:48]}…")
        if d.tags:
            print(f"  tags:       {', '.join(d.tags)}")
    return 0 if ok else 2


if __name__ == "__main__":
    import sys
    sys.exit(main())
