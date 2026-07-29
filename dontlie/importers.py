"""dontlie import — convert receipts from competitor formats into a Don't-Lie vault.

Supported formats:
    - obsigna     (Obsigna receipt protocol, JSON)
    - halo-record (halo-record NDJSON export)
    - aulite      (Aulite PDF/JSON export)
    - generic-jsonl  (one JSON receipt per line, any compatible shape)

This is interop as a feature. The buyer has data in a competitor's
format; we let them bring it in without losing history.

Conversion is best-effort: we map the competitor's fields onto the
Don't-Lie schema, generate fresh signatures under the operator's
active key (so the imported receipts are now signed by the operator
and chain-linked to the existing vault), and write them as a new
segment at the tail of the chain. The original competitor receipts
are preserved in `extra._imported_from` for traceability.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Iterator

from . import sign as signing
from . import storage


@dataclass
class ImportResult:
    imported: int = 0
    skipped: int = 0
    errors: list[str] = field(default_factory=list)
    first_id: int | None = None
    last_id: int | None = None


# ---- format detection -------------------------------------------------------

def detect_format(path: Path) -> str:
    """Sniff the file format from the content."""
    text = path.read_text(errors="ignore")
    head = text[:2000]
    if "obsigna" in head.lower() or '"issuer"' in head and '"action"' in head:
        return "obsigna"
    if '"halo"' in head or '"halo-record"' in head:
        return "halo-record"
    if "aulite" in head.lower():
        return "aulite"
    # fall through to JSONL / JSON
    return "generic-jsonl"


# ---- per-format converters --------------------------------------------------

def _import_obsigna(path: Path) -> Iterator[dict]:
    """Yield Don't-Lie-compatible receipt dicts from an Obsigna export."""
    data = json.loads(path.read_text())
    receipts = data.get("receipts") or data.get("items") or (data if isinstance(data, list) else [])
    for r in receipts:
        try:
            prompt = r.get("principal", {}).get("input", "")
            response = r.get("outcome", {}).get("result", "")
            model = r.get("principal", {}).get("model", "unknown")
            ts = r.get("issued_at") or r.get("timestamp") or r.get("time", "")
            yield {
                "model": model,
                "prompt": prompt if isinstance(prompt, str) else json.dumps(prompt),
                "response": response if isinstance(response, str) else json.dumps(response),
                "timestamp": ts,
                "tags": [f"imported_from:obsigna", f"obsigna_id:{r.get('id', '?')}"],
                "extra": {"_imported_from": "obsigna", "obsigna": r},
            }
        except Exception as exc:
            raise ValueError(f"obsigna record parse error: {exc}")


def _import_halo(path: Path) -> Iterator[dict]:
    """Yield receipt dicts from a halo-record NDJSON export."""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            yield {
                "model": r.get("model", "unknown"),
                "prompt": r.get("input") or r.get("prompt") or "",
                "response": r.get("output") or r.get("response") or "",
                "timestamp": r.get("timestamp") or r.get("time") or "",
                "tags": [f"imported_from:halo-record", f"halo_id:{r.get('id', '?')}"],
                "extra": {"_imported_from": "halo-record", "halo": r},
            }
        except Exception as exc:
            raise ValueError(f"halo record parse error: {exc}")


def _import_aulite(path: Path) -> Iterator[dict]:
    """Yield receipt dicts from an Aulite JSON export."""
    data = json.loads(path.read_text())
    entries = data.get("entries") or data.get("audit_log") or (data if isinstance(data, list) else [])
    for r in entries:
        try:
            req = r.get("request") or {}
            resp = r.get("response") or {}
            yield {
                "model": req.get("model", "unknown"),
                "prompt": json.dumps(req.get("messages") or req.get("input") or ""),
                "response": json.dumps(resp.get("content") or resp.get("output") or ""),
                "timestamp": r.get("ts") or r.get("timestamp") or "",
                "tags": [f"imported_from:aulite", f"aulite_id:{r.get('id', '?')}"],
                "extra": {"_imported_from": "aulite", "aulite": r},
            }
        except Exception as exc:
            raise ValueError(f"aulite record parse error: {exc}")


def _import_generic_jsonl(path: Path) -> Iterator[dict]:
    """Yield receipt dicts from a generic JSONL file with model/prompt/response."""
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            yield {
                "model": r.get("model", "unknown"),
                "prompt": r.get("prompt", ""),
                "response": r.get("response", ""),
                "timestamp": r.get("timestamp", ""),
                "tags": ["imported_from:generic-jsonl"],
                "extra": {"_imported_from": "generic-jsonl", "original": r},
            }
        except Exception as exc:
            raise ValueError(f"generic record parse error: {exc}")


CONVERTERS = {
    "obsigna": _import_obsigna,
    "halo-record": _import_halo,
    "aulite": _import_aulite,
    "generic-jsonl": _import_generic_jsonl,
}


# ---- import orchestration --------------------------------------------------

def import_file(path: Path, *, format: str | None = None) -> ImportResult:
    """Import receipts from a file. Returns a summary of what happened."""
    storage.init()
    fmt = format or detect_format(path)
    if fmt not in CONVERTERS:
        return ImportResult(errors=[f"unknown format: {fmt!r}"])
    converter = CONVERTERS[fmt]
    result = ImportResult()
    for receipt_dict in converter(path):
        try:
            r = storage.append(
                model=receipt_dict["model"],
                prompt=receipt_dict["prompt"],
                response=receipt_dict["response"],
                tags=receipt_dict.get("tags", []),
                extra=receipt_dict.get("extra", {}),
            )
            if result.first_id is None:
                result.first_id = r.id
            result.last_id = r.id
            result.imported += 1
        except Exception as exc:
            result.skipped += 1
            result.errors.append(str(exc))
    return result


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie import", description=__doc__)
    parser.add_argument("path", type=Path, help="file to import (JSON or JSONL)")
    parser.add_argument("--format", default=None,
                        choices=["obsigna", "halo-record", "aulite", "generic-jsonl"],
                        help="force a specific format (default: auto-detect)")
    args = parser.parse_args(argv)
    if not args.path.exists():
        print(f"file not found: {args.path}", file=sys.stderr)
        return 1
    result = import_file(args.path, format=args.format)
    print(f"format:        {args.format or detect_format(args.path)}")
    print(f"imported:      {result.imported}")
    print(f"skipped:       {result.skipped}")
    if result.first_id is not None:
        print(f"first id:      #{result.first_id}")
    if result.last_id is not None:
        print(f"last id:       #{result.last_id}")
    if result.errors:
        print("errors:")
        for e in result.errors[:10]:
            print(f"  - {e}")
        if len(result.errors) > 10:
            print(f"  ... and {len(result.errors) - 10} more")
    return 0 if not result.errors else 2


if __name__ == "__main__":
    sys.exit(main())
