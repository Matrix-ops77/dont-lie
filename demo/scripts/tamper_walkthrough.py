"""Tamper walkthrough using Don't-Lie's production verifier.

Operates on the isolated vault produced by ``run_offline_demo.sh``. It mutates
one SQLite field, shows receipt-level verification errors, restores the signed
record from the JSONL export, and verifies the original chain again.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import sys
from pathlib import Path

from dontlie import storage


def _report(db_path: Path) -> storage.VerificationReport:
    storage.DB_PATH = db_path
    return storage.verify_chain_report()


def _print_report(label: str, report: storage.VerificationReport) -> None:
    print(f"{label}: {report.ok_count} ok, {report.bad_count} bad")
    for issue in report.issues:
        receipt = issue.receipt_id if issue.receipt_id is not None else "export"
        print(f"  receipt {receipt}: {issue.reason}")


def _receipt_two(db_path: Path) -> storage.Receipt:
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        row = conn.execute("SELECT * FROM receipts WHERE id=2").fetchone()
    if row is None:
        raise RuntimeError("receipt #2 is missing")
    return storage._row_to_receipt(row)


def _restore_from_jsonl(db_path: Path, jsonl_path: Path) -> int:
    records = [
        json.loads(line)
        for line in jsonl_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    with sqlite3.connect(db_path) as conn:
        for record in records:
            conn.execute(
                """
                UPDATE receipts
                SET timestamp=?, model=?, prompt=?, response=?, parent_id=?,
                    key_id=?, payload_sha256=?, signature=?, tags=?, extra=?
                WHERE id=?
                """,
                (
                    record["timestamp"],
                    record["model"],
                    record["prompt"],
                    record["response"],
                    record["parent_id"],
                    record["key_id"],
                    record["payload_sha256"],
                    record["signature"],
                    json.dumps(record["tags"]),
                    json.dumps(record["extra"]),
                    record["id"],
                ),
            )
    return len(records)


def main(argv: list[str] | None = None) -> int:
    args = argv if argv is not None else sys.argv[1:]
    work = Path(args[0]) if args else Path("demo/work")
    db_path = work / "vault.db"
    jsonl_path = work / "receipts.jsonl"
    if not db_path.exists() or not jsonl_path.exists():
        print(
            f"FAIL: missing {db_path} or {jsonl_path}; run the offline demo first",
            file=sys.stderr,
        )
        return 1

    print("=== STAGE 1: verify clean vault with production verifier ===")
    clean = _report(db_path)
    _print_report("clean", clean)
    if not clean.valid:
        return 2

    original = _receipt_two(db_path)
    print("\n=== STAGE 2: mutate receipt #2 directly in SQLite ===")
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            "UPDATE receipts SET response=? WHERE id=2",
            ("TAMPERED: Paris was replaced after signing",),
        )
    print("changed only the response column; hash and signature were not touched")

    print("\n=== STAGE 3: verify tampered vault ===")
    tampered = _report(db_path)
    _print_report("tampered", tampered)
    if tampered.valid:
        print("FAIL: verifier accepted a mutated receipt", file=sys.stderr)
        return 2

    print("\n=== STAGE 4: show the exact hash mismatch ===")
    changed = _receipt_two(db_path)
    recomputed = hashlib.sha256(storage._canonical_payload(changed)).hexdigest()
    print(f"  signed/stored sha256: {changed.payload_sha256}")
    print(f"  recomputed sha256:    {recomputed}")
    print(f"  match: {changed.payload_sha256 == recomputed}")

    print("\n=== STAGE 5: restore the original signed records ===")
    restored_count = _restore_from_jsonl(db_path, jsonl_path)
    print(f"restored {restored_count} records from receipts.jsonl")

    print("\n=== STAGE 6: verify restored vault ===")
    restored = _report(db_path)
    _print_report("restored", restored)
    if not restored.valid:
        return 2
    if _receipt_two(db_path).payload_sha256 != original.payload_sha256:
        print("FAIL: receipt #2 was not restored exactly", file=sys.stderr)
        return 2

    print("\n=== CONCLUSION ===")
    print("Don't-Lie proves that the local recorder signed this exact record and")
    print("that its signed, hash-linked history has not been silently rewritten.")
    print("It does not prove that a model answer was truthful or independently")
    print("attest which remote provider generated it.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
