"""Waitlist endpoint stub.

The static landing page POSTs to ``/api/waitlist``. This stub is a
stdlib-only HTTP server that accepts the JSON body, persists it to a
local file, and returns a 200 OK. It is intentionally minimal so that
the site can be demoed without a full backend.

Run:

    python3 -m dontlie.site.waitlist --port 8080

Note: this is a stub. Production deployment should replace it with
something that writes to a real CRM (HubSpot, etc.) and emits
appropriate rate limits and auth.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DUMP = Path(os.environ.get("DONTLIE_WAITLIST_DUMP", ROOT / "waitlist.jsonl"))


class WaitlistHandler(BaseHTTPRequestHandler):
    dump_path: Path = DEFAULT_DUMP

    def do_POST(self) -> None:
        if self.path != "/api/waitlist":
            self.send_error(404, "not found")
            return
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length else "{}"
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_error(400, "invalid JSON")
            return
        record = {
            "received_at": datetime.now(timezone.utc).isoformat(),
            **payload,
        }
        self.dump_path.parent.mkdir(parents=True, exist_ok=True)
        with self.dump_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record) + "\n")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))

    def do_GET(self) -> None:
        if self.path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"ok": True}).encode("utf-8"))
            return
        self.send_error(404, "not found")

    def log_message(self, fmt: str, *args: object) -> None:
        # Keep stderr tidy; toggle off if you want logs.
        pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Don't-Lie waitlist stub")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--dump", type=Path, default=DEFAULT_DUMP)
    args = parser.parse_args(argv)
    WaitlistHandler.dump_path = args.dump
    httpd = ThreadingHTTPServer(("127.0.0.1", args.port), WaitlistHandler)
    print(f"waitlist stub listening on http://127.0.0.1:{args.port}/api/waitlist", file=sys.stderr)
    print(f"appending leads to {args.dump}", file=sys.stderr)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
