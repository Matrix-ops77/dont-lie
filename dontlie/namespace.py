"""dontlie namespace — multi-tenant vault isolation.

A namespace is a named scope inside one vault. Every receipt, decision,
annotation, and batch belongs to exactly one namespace. The default
namespace is `default`.

Use cases:
    - one vault per machine, many customers/teams/projects sharing
    - per-tenant retention policies (a customer goes away, delete
      only their namespace, not the whole vault)
    - per-tenant key management (each namespace can have its own
      signing key)
    - per-tenant reporting (a compliance officer queries one
      namespace at a time)

CLI:
    dontlie namespace list
    dontlie namespace create --name acme-corp
    dontlie namespace use acme-corp           # sets the env var
    dontlie namespace delete acme-corp
    dontlie namespace show acme-corp
    dontlie namespace stats acme-corp

The proxy reads `DONTLIE_NAMESPACE` from the environment to decide
which namespace's receipts to write. CLI commands use
`--namespace NAME` to override.
"""
from __future__ import annotations

import json
import os
import sqlite3
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from . import sign as signing
from . import storage


SCHEMA = """
CREATE TABLE IF NOT EXISTS namespaces (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    created_at      TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    key_id          TEXT,                     -- the namespace's own signing key id (optional)
    tags            TEXT    NOT NULL DEFAULT '[]',
    extra           TEXT    NOT NULL DEFAULT '{}'
);
"""


@dataclass
class Namespace:
    id: int
    name: str
    created_at: str
    description: str
    key_id: str | None
    tags: list[str] = field(default_factory=list)
    extra: dict[str, object] = field(default_factory=dict)


DEFAULT_NAMESPACE = "default"


def init() -> None:
    conn = storage._connect()
    try:
        conn.executescript(SCHEMA)
        # Ensure the default namespace exists
        cur = conn.execute("SELECT id FROM namespaces WHERE name = ?", (DEFAULT_NAMESPACE,))
        if cur.fetchone() is None:
            conn.execute(
                "INSERT INTO namespaces (name, created_at, description) VALUES (?, ?, ?)",
                (DEFAULT_NAMESPACE, datetime.now(timezone.utc).isoformat(), "default namespace"),
            )
        conn.commit()
    finally:
        conn.close()


def _current() -> str:
    """The namespace name for the current operation, from env var or default."""
    return os.environ.get("DONTLIE_NAMESPACE", DEFAULT_NAMESPACE)


def create(name: str, *, description: str = "", tags: Iterable[str] = ()) -> Namespace:
    if not name or not name.replace("_", "").replace("-", "").isalnum():
        raise ValueError(f"namespace name must be alphanumeric (got {name!r})")
    init()
    conn = storage._connect()
    try:
        cur = conn.execute(
            "INSERT INTO namespaces (name, created_at, description, tags, extra) VALUES (?, ?, ?, ?, ?)",
            (name, datetime.now(timezone.utc).isoformat(), description,
             json.dumps(list(tags)), "{}"),
        )
        ns_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError:
        conn.close()
        raise ValueError(f"namespace {name!r} already exists")
    finally:
        conn.close()
    return get(name)


def get(name: str) -> Namespace | None:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM namespaces WHERE name = ?", (name,))
        row = cur.fetchone()
    finally:
        conn.close()
    if row is None:
        return None
    return Namespace(
        id=row[0], name=row[1], created_at=row[2], description=row[3],
        key_id=row[4], tags=json.loads(row[5] or "[]"), extra=json.loads(row[6] or "{}"),
    )


def list_all() -> list[Namespace]:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT * FROM namespaces ORDER BY id")
        rows = cur.fetchall()
    finally:
        conn.close()
    return [
        Namespace(
            id=r[0], name=r[1], created_at=r[2], description=r[3],
            key_id=r[4], tags=json.loads(r[5] or "[]"), extra=json.loads(r[6] or "{}"),
        )
        for r in rows
    ]


def delete(name: str) -> int:
    """Delete a namespace and ALL its receipts. Returns the number of receipts removed."""
    if name == DEFAULT_NAMESPACE:
        raise ValueError(f"cannot delete the {DEFAULT_NAMESPACE!r} namespace")
    init()
    ns = get(name)
    if ns is None:
        raise ValueError(f"namespace {name!r} not found")
    conn = storage._connect()
    try:
        # Count receipts in this namespace
        cur = conn.execute("SELECT COUNT(*) FROM receipts WHERE namespace = ?", (name,))
        count = cur.fetchone()[0]
        # Delete them
        conn.execute("DELETE FROM receipts WHERE namespace = ?", (name,))
        conn.execute("DELETE FROM namespaces WHERE name = ?", (name,))
        conn.commit()
    finally:
        conn.close()
    return count


def stats(name: str) -> dict:
    init()
    conn = storage._connect()
    try:
        cur = conn.execute("SELECT COUNT(*) FROM receipts WHERE namespace = ?", (name,))
        total = cur.fetchone()[0]
        cur = conn.execute("SELECT DISTINCT model FROM receipts WHERE namespace = ? AND model IS NOT NULL", (name,))
        models = [r[0] for r in cur.fetchall()]
        cur = conn.execute("SELECT MIN(timestamp), MAX(timestamp) FROM receipts WHERE namespace = ?", (name,))
        first, last = cur.fetchone()
    finally:
        conn.close()
    return {
        "namespace": name,
        "total_receipts": total,
        "distinct_models": models,
        "first_receipt_at": first,
        "last_receipt_at": last,
    }


# ---- CLI -------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie namespace", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list all namespaces")
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    p_create = sub.add_parser("create", help="create a new namespace")
    p_create.add_argument("--name", required=True)
    p_create.add_argument("--description", default="")
    p_create.set_defaults(func=lambda a: _cmd_create(a))

    p_use = sub.add_parser("use", help="print the export command to set this as the current namespace")
    p_use.add_argument("name")
    p_use.set_defaults(func=lambda a: _cmd_use(a))

    p_delete = sub.add_parser("delete", help="delete a namespace and all its receipts (irreversible)")
    p_delete.add_argument("name")
    p_delete.add_argument("--force", action="store_true", help="skip confirmation")
    p_delete.set_defaults(func=lambda a: _cmd_delete(a))

    p_show = sub.add_parser("show", help="show details of a namespace")
    p_show.add_argument("name")
    p_show.set_defaults(func=lambda a: _cmd_show(a))

    p_stats = sub.add_parser("stats", help="show stats for a namespace")
    p_stats.add_argument("name")
    p_stats.set_defaults(func=lambda a: _cmd_stats(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_list(args) -> int:
    nss = list_all()
    if not nss:
        print("no namespaces (this is a bug — default should exist)")
        return 1
    for ns in nss:
        marker = " *" if ns.name == _current() else ""
        print(f"{ns.id:3d}  {ns.name}{marker}  (created {ns.created_at[:10]})")
    print(f"\ncurrent: {_current()!r}  (set via DONTLIE_NAMESPACE env var)")
    return 0


def _cmd_create(args) -> int:
    try:
        ns = create(args.name, description=args.description)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"namespace {ns.name!r} created (id={ns.id})")
    print(f"  switch to it:  export DONTLIE_NAMESPACE={ns.name}")
    return 0


def _cmd_use(args) -> int:
    if get(args.name) is None:
        print(f"namespace {args.name!r} not found", file=sys.stderr)
        return 1
    print(f"export DONTLIE_NAMESPACE={args.name}")
    return 0


def _cmd_delete(args) -> int:
    if not args.force:
        print("warning: this deletes all receipts in the namespace. use --force to confirm.",
              file=sys.stderr)
        return 2
    try:
        n = delete(args.name)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"deleted namespace {args.name!r} and {n} receipts")
    return 0


def _cmd_show(args) -> int:
    ns = get(args.name)
    if ns is None:
        print(f"namespace {args.name!r} not found", file=sys.stderr)
        return 1
    print(f"Namespace {ns.name!r} (id={ns.id})")
    print(f"  created:   {ns.created_at}")
    print(f"  key_id:    {ns.key_id or '(inherits the vault key)'}")
    if ns.description:
        print(f"  notes:     {ns.description}")
    if ns.tags:
        print(f"  tags:      {', '.join(ns.tags)}")
    return 0


def _cmd_stats(args) -> int:
    s = stats(args.name)
    if s["total_receipts"] == 0 and s["first_receipt_at"] is None:
        print(f"namespace {args.name!r} not found or empty", file=sys.stderr)
        return 1
    print(f"Namespace {s['namespace']!r}: {s['total_receipts']} receipts")
    if s["distinct_models"]:
        print(f"  models:        {', '.join(s['distinct_models'])}")
    if s["first_receipt_at"]:
        print(f"  first receipt: {s['first_receipt_at']}")
    if s["last_receipt_at"]:
        print(f"  last receipt:  {s['last_receipt_at']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
