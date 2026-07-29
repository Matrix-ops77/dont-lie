"""dontlie witness-service — a stdlib HTTP server that co-signs receipt hashes.

This is the public, no-signup witness notary. Anyone with a receipt
hash can POST it here and get back a co-signature under this service's
key. The co-signature proves that at time T (the time this service
received the request), a particular hash existed.

This is the "Bitcoin moment" — a free, public, no-permission service
that turns a receipt into evidence that doesn't require trusting the
operator. Anyone in the world can POST a hash. Anyone in the world
can verify the co-signature against the public key published on this
service's /pubkey endpoint.

The service never sees the receipt content. It sees only:
    - the receipt's SHA-256 hash
    - the operator's key fingerprint
    - a nonce (operator-generated, included in the co-signature)
    - the receipt's parent SHA-256 (so the chain is anchored too)

This closes Reasonable Doubt #5. The cost: a 1-10ms HTTP call to a
public endpoint, which the operator can self-host or use the hosted
version.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import secrets
import sys
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from . import sign as signing
from . import storage


SERVICE_NAME = "dontlie-witness-service"
SERVICE_VERSION = "0.1.0"


# ---- service state ----------------------------------------------------------

class WitnessState:
    def __init__(self, key_dir: Path) -> None:
        self.key_dir = Path(key_dir)
        self.key_dir.mkdir(parents=True, exist_ok=True)
        # Reuse the dontlie signing module to generate/load the service key
        signing.KEY_DIR = self.key_dir
        signing.PRIVATE_FILE = self.key_dir / "witness.key"
        signing.PUBLIC_FILE = self.key_dir / "witness.pub"
        signing.KEY_ID_FILE = self.key_dir / "witness.key_id"
        signing._ensure_dir()
        if not signing.PRIVATE_FILE.exists():
            signing.generate()
        self.kp = signing.load()
        # Counters for observability
        self.attestations: list[dict] = []
        self.requests = 0

    def pubkey_pem(self) -> str:
        return signing.PUBLIC_FILE.read_text()

    def key_id(self) -> str:
        return self.kp.key_id

    def attest(self, *, receipt_sha256: str, operator_key_id: str,
               parent_sha256: str | None, nonce: str) -> dict:
        """Issue a co-signature attestation for one receipt hash."""
        self.requests += 1
        now = datetime.now(timezone.utc).isoformat()
        # The co-signature covers the canonical tuple:
        #   (receipt_sha256, operator_key_id, parent_sha256 or "", nonce, service_key_id, now)
        msg = json.dumps({
            "receipt_sha256": receipt_sha256,
            "operator_key_id": operator_key_id,
            "parent_sha256": parent_sha256 or "",
            "nonce": nonce,
            "service": SERVICE_NAME,
            "service_version": SERVICE_VERSION,
            "service_key_id": self.kp.key_id,
            "issued_at": now,
        }, sort_keys=True, separators=(",", ":")).encode("utf-8")
        attestation_sig = signing.sign_bytes(self.kp, msg)
        attestation = {
            "service": SERVICE_NAME,
            "service_version": SERVICE_VERSION,
            "service_key_id": self.kp.key_id,
            "issued_at": now,
            "receipt_sha256": receipt_sha256,
            "operator_key_id": operator_key_id,
            "parent_sha256": parent_sha256,
            "nonce": nonce,
            "signature": attestation_sig,
        }
        # Persist for the service's own audit
        self.attestations.append(attestation)
        return attestation


# ---- HTTP handler -----------------------------------------------------------

class WitnessHandler(BaseHTTPRequestHandler):
    server_version = f"{SERVICE_NAME}/{SERVICE_VERSION}"

    def log_message(self, fmt: str, *args) -> None:
        sys.stderr.write(f"[witness] {self.address_string()} {fmt % args}\n")

    def _send_json(self, payload, status: int = 200) -> None:
        body = json.dumps(payload, sort_keys=True, indent=2, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Access-Control-Allow-Origin", "*")  # CORS so a browser can call this
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/healthz", "/health"):
            return self._send_json({
                "service": SERVICE_NAME,
                "version": SERVICE_VERSION,
                "key_id": self.server.state.key_id(),
                "ok": True,
                "endpoints": {
                    "GET  /": "this banner",
                    "GET  /healthz": "liveness check (same as /)",
                    "GET  /pubkey": "the service's signing public key (PEM)",
                    "GET  /stats": "request and attestation counts",
                    "POST /attest": "request a co-signature for a receipt hash",
                },
                "docs": "https://github.com/Matrix-ops77/dontlie/blob/main/docs/WITNESS_SERVICE.md",
            })
        if self.path == "/pubkey":
            return self._send_json({
                "service": SERVICE_NAME,
                "key_id": self.server.state.key_id(),
                "public_key_pem": self.server.state.pubkey_pem(),
            })
        if self.path == "/stats":
            return self._send_json({
                "requests": self.server.state.requests,
                "attestations": len(self.server.state.attestations),
            })
        if self.path == "/attestations":
            # return the most recent 100 attestations (this is the public ledger)
            recent = self.server.state.attestations[-100:]
            return self._send_json({"attestations": recent})
        return self._send_json({"error": "not found"}, status=HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:  # noqa: N802
        if self.path != "/attest":
            return self._send_json({"error": "unknown endpoint"}, status=HTTPStatus.NOT_FOUND)
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length)
            req = json.loads(body)
        except Exception as exc:
            return self._send_json({"error": f"invalid JSON: {exc}"}, status=400)
        receipt_sha = req.get("receipt_sha256") or ""
        operator_key_id = req.get("operator_key_id") or ""
        parent_sha = req.get("parent_sha256")
        nonce = req.get("nonce") or secrets.token_hex(16)
        if not receipt_sha or not operator_key_id:
            return self._send_json(
                {"error": "receipt_sha256 and operator_key_id are required"},
                status=400,
            )
        if not _is_valid_sha256(receipt_sha):
            return self._send_json(
                {"error": f"receipt_sha256 is not a valid SHA-256 hex digest"},
                status=400,
            )
        attestation = self.server.state.attest(
            receipt_sha256=receipt_sha,
            operator_key_id=operator_key_id,
            parent_sha256=parent_sha,
            nonce=nonce,
        )
        return self._send_json(attestation)


def _is_valid_sha256(s: str) -> bool:
    if len(s) != 64:
        return False
    try:
        int(s, 16)
        return True
    except ValueError:
        return False


# ---- server -----------------------------------------------------------------

class WitnessServer(ThreadingHTTPServer):
    def __init__(self, address, handler, state: WitnessState):
        super().__init__(address, handler)
        self.state = state


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="dontlie witness-service", description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=9099)
    parser.add_argument("--key-dir", type=Path,
                        default=Path.home() / ".config" / "dontlie" / "witness",
                        help="where to store the service's signing key")
    args = parser.parse_args(argv)
    state = WitnessState(args.key_dir)
    server = WitnessServer((args.host, args.port), WitnessHandler, state)
    print(f"{SERVICE_NAME} v{SERVICE_VERSION} — http://{args.host}:{args.port}/")
    print(f"  service key_id: {state.key_id()}")
    print(f"  public key:     {args.key_dir}/witness.pub")
    print("  endpoints: GET /, /pubkey, /stats, /attestations; POST /attest")
    print("  press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down…")
        server.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
