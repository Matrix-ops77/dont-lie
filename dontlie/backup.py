"""dontlie backup — safe, atomic copy of the live vault to a snapshot file.

Use this BEFORE running any test work, BEFORE upgrading the package,
or any time you want a restorable point in time.

Why this exists: in v0.3.0/v0.3.1 a test-isolation bug wrote test
receipts into the production vault and the original data was lost
because no snapshot existed. ``dontlie backup`` is the safety net.

Implementation note: uses SQLite's online backup API
(``Connection.backup``) which is safe to call while the vault is open
by another process. That's a property ``shutil.copy2`` doesn't
give us — the proxy could be writing to the vault at the moment of
copy, and a naive file copy can produce a torn snapshot.
"""
from __future__ import annotations

import argparse
import os
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import storage


def _default_snapshot_path(out_dir: Path | None = None) -> Path:
    """Build a timestamped snapshot filename in ``out_dir`` (default:
    ``~/.local/share/dontlie/backups/``)."""
    out_dir = out_dir or Path.home() / ".local" / "share" / "dontlie" / "backups"
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return out_dir / f"vault-{ts}.db"


def backup_vault(
    src: Path | None = None,
    dst: Path | None = None,
) -> Path:
    """Snapshot ``src`` (default: the live vault) to ``dst`` (default:
    ``~/.local/share/dontlie/backups/vault-<ts>.db``). Returns the
    destination path on success.

    Uses SQLite's online backup API so a concurrent writer (the proxy)
    cannot tear the snapshot. The destination file is written
    atomically: we write to ``<dst>.tmp`` then ``os.replace`` over the
    final path.
    """
    src = src or storage.DB_PATH
    if not src.exists():
        raise FileNotFoundError(f"vault not found: {src}")
    dst = dst or _default_snapshot_path()
    dst.parent.mkdir(parents=True, exist_ok=True)

    tmp = dst.with_suffix(dst.suffix + ".tmp")
    # Online backup: opens a second connection, uses SQLite's
    # incremental copy API, and is safe across processes.
    src_conn = sqlite3.connect(str(src))
    try:
        dst_conn = sqlite3.connect(str(tmp))
        try:
            src_conn.backup(dst_conn)
        finally:
            dst_conn.close()
    finally:
        src_conn.close()
    # Atomic replace so partial backups never appear at dst.
    os.replace(tmp, dst)
    return dst


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        prog="dontlie backup",
        description=__doc__,
    )
    p.add_argument(
        "--src", dest="src", type=Path, default=None,
        help="path to the live vault (default: $DONTLIE_DB or "
             "~/.local/share/dontlie/vault.db)",
    )
    p.add_argument(
        "--dst", dest="dst", type=Path, default=None,
        help="snapshot path (default: ~/.local/share/dontlie/backups/"
             "vault-<UTC-timestamp>.db)",
    )
    p.add_argument(
        "--list", dest="list_only", action="store_true",
        help="list existing snapshots and exit",
    )
    args = p.parse_args(argv)

    if args.list_only:
        backups_dir = Path.home() / ".local" / "share" / "dontlie" / "backups"
        if not backups_dir.exists():
            print(f"no backups at {backups_dir}")
            return 0
        snaps = sorted(backups_dir.glob("vault-*.db"))
        if not snaps:
            print(f"no backups at {backups_dir}")
            return 0
        for snap in snaps:
            size = snap.stat().st_size
            mtime = datetime.fromtimestamp(snap.stat().st_mtime, tz=timezone.utc)
            print(f"  {snap.name}  {size:>10} bytes  {mtime.isoformat()}")
        return 0

    try:
        snapshot = backup_vault(args.src, args.dst)
    except FileNotFoundError as exc:
        print(f"backup failed: {exc}", file=sys.stderr)
        return 1
    size = snapshot.stat().st_size
    print(f"backed up vault to {snapshot}  ({size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
