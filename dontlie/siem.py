"""dontlie siem — emit receipts in OCSF and Splunk ECS field formats.

Two formats:
    ocsf   — Open Cybersecurity Schema Framework (https://ocsf.io)
             Maps each receipt to an `api.activity` event class.
    ecs    — Elastic Common Schema (https://www.elastic.co/guide/en/ecs/current/)
             Maps each receipt to an `event` of category `web` and type `info`.

Both formats normalize the receipt fields so the SIEM doesn't have to.
This is a "make the SIEM happy" feature: Splunk, Datadog, Elastic, Sumo
all have field-naming conventions. Emitting in the right format means
the receipt lands in the right place automatically, with no field
extraction rules in the SIEM.
"""
from __future__ import annotations

import base64
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Iterable

from . import storage


def to_ocsf(receipt) -> dict:
    """Convert a Receipt to an OCSF api.activity event."""
    ts = receipt.timestamp
    return {
        # OCSF required envelope
        "activity_id": receipt.id,
        "activity_name": "AI call signed and recorded by Don't-Lie",
        "category_name": "Application Activity",
        "category_uid": 5,
        "class_name": "API Activity",
        "class_uid": 6003,
        "metadata": {
            "product": {
                "name": "Don't-Lie",
                "version": getattr(storage, "__version__", "0.3.0"),
                "vendor_name": "Don't-Lie",
            },
            "version": "1.0.0",
        },
        "severity": "Informational",
        "severity_id": 1,
        "status": "Success" if receipt.parent_id is not None else "Other",
        "status_id": 1 if receipt.parent_id is not None else 99,
        "time": int(_parse_ts(ts).timestamp() * 1000),
        "timestamp": ts,
        "type_uid": 600301,
        # OCSF api.activity fields
        "actor": {
            "user": {"uid": receipt.key_id, "name": receipt.key_id, "type": "Key"},
        },
        "api": {
            "operation": "chat.completions",
            "service": {"name": receipt.model or "unknown"},
            "version": "v1",
            "request": {
                "data": receipt.prompt,
                "flags": [],
                "uid": str(receipt.id),
            },
            "response": {
                "data": receipt.response,
                "code": 200,
                "error": "",
            },
        },
        "dontlie": {
            "receipt_id": receipt.id,
            "parent_id": receipt.parent_id,
            "payload_sha256": receipt.payload_sha256,
            "signature": receipt.signature,
            "key_id": receipt.key_id,
            "tags": list(receipt.tags or []),
        },
        "unmapped": {
            "extra": receipt.extra,
        },
    }


def to_ecs(receipt) -> dict:
    """Convert a Receipt to a Splunk/Elastic Common Schema event."""
    ts = receipt.timestamp
    return {
        # ECS required fields
        "@timestamp": ts,
        "ecs": {"version": "8.0.0"},
        "event": {
            "kind": "event",
            "category": ["web", "authentication"],
            "type": ["info"],
            "action": "ai-call-signed",
            "outcome": "success",
            "id": str(receipt.id),
            "created": ts,
        },
        "host": {
            "name": "dontlie-local",
        },
        "process": {
            "name": "dontlie-proxy",
        },
        "user": {
            "id": receipt.key_id,
            "name": receipt.key_id,
        },
        "http": {
            "request": {
                "method": "POST",
                "body": {"content": receipt.prompt},
            },
            "response": {
                "status_code": 200,
                "body": {"content": receipt.response},
            },
        },
        "url": {
            "path": "/v1/chat/completions",
        },
        "user_agent": {
            "original": f"openai-python/{receipt.model}",
        },
        "dontlie": {
            "receipt_id": receipt.id,
            "parent_id": receipt.parent_id,
            "model": receipt.model,
            "payload_sha256": receipt.payload_sha256,
            "signature": receipt.signature,
            "key_id": receipt.key_id,
            "tags": list(receipt.tags or []),
            "extra": receipt.extra,
        },
    }


def _parse_ts(ts: str) -> datetime:
    try:
        return datetime.fromisoformat(ts)
    except Exception:
        return datetime.now(timezone.utc)


# ---- CLI streaming ----------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie siem", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_tail = sub.add_parser("tail", help="stream receipts in OCSF or ECS format")
    p_tail.add_argument("--format", choices=["ocsf", "ecs"], required=True)
    p_tail.add_argument("--last", type=int, default=20, help="number of recent receipts to emit")
    p_tail.set_defaults(func=lambda a: _cmd_tail(a))

    p_convert = sub.add_parser("convert", help="convert one receipt to OCSF/ECS JSON")
    p_convert.add_argument("receipt_id", type=int)
    p_convert.add_argument("--format", choices=["ocsf", "ecs"], required=True)
    p_convert.set_defaults(func=lambda a: _cmd_convert(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_tail(args) -> int:
    storage.init()
    receipts = storage.list_receipts(limit=args.last)
    formatter = to_ocsf if args.format == "ocsf" else to_ecs
    for r in receipts:
        sys.stdout.write(json.dumps(formatter(r), default=str) + "\n")
    sys.stdout.flush()
    return 0


def _cmd_convert(args) -> int:
    storage.init()
    r = storage.get_receipt(args.receipt_id)
    if r is None:
        print(f"receipt {args.receipt_id} not found", file=sys.stderr)
        return 1
    formatter = to_ocsf if args.format == "ocsf" else to_ecs
    print(json.dumps(formatter(r), indent=2, sort_keys=True, default=str))
    return 0


if __name__ == "__main__":
    sys.exit(main())
