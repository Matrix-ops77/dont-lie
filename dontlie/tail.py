"""dontlie tail — stream new receipts as they land.

Pipe-friendly NDJSON output for SIEM ingestion (Splunk, Datadog, ELK,
Sumo). Each line is one receipt as a JSON object.

Usage:
    dontlie tail --follow              # stream new receipts as they arrive
    dontlie tail --follow --json       # same, but always JSON
    dontlie tail --last 100 --json     # dump last 100 receipts as JSONL
    dontlie tail --follow | curl -X POST https://splunk.example/hec -d @-

The `--follow` mode polls the vault every 2s. Each line includes the
vault path and a content hash so an SIEM can dedup.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict

from . import storage


def _emit(receipt: storage.Receipt, *, as_json: bool) -> None:
    if as_json:
        d = asdict(receipt)
        d["_source"] = "dontlie"
        d["_vault"] = str(storage.DB_PATH)
        sys.stdout.write(json.dumps(d, default=str) + "\n")
    else:
        sys.stdout.write(
            f"#{receipt.id}  {receipt.timestamp}  [{receipt.model}]  "
            f"parent={receipt.parent_id}  key={receipt.key_id[:8]}\n"
        )
    sys.stdout.flush()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dontlie tail", description=__doc__)
    parser.add_argument("--follow", "-f", action="store_true", help="poll for new receipts")
    parser.add_argument("--last", type=int, default=20, help="show the last N (default: 20)")
    parser.add_argument("--interval", type=float, default=2.0, help="poll interval in seconds (default: 2)")
    parser.add_argument("--json", action="store_true", help="emit JSONL (one receipt per line)")
    args = parser.parse_args(argv)

    storage.init()
    seen: set[int] = set()

    def dump_recent() -> int:
        receipts = storage.list_receipts(limit=args.last)
        count = 0
        for r in receipts:
            if r.id in seen:
                continue
            _emit(r, as_json=args.json)
            seen.add(r.id)
            count += 1
        return count

    if not args.follow:
        dump_recent()
        return 0

    # follow mode: emit existing, then poll
    last_count = dump_recent()
    try:
        while True:
            time.sleep(args.interval)
            current = storage.count()
            if current > last_count:
                # new receipts landed
                receipts = storage.list_receipts(limit=current)
                for r in receipts:
                    if r.id in seen:
                        continue
                    _emit(r, as_json=args.json)
                    seen.add(r.id)
                last_count = current
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
