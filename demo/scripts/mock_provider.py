"""Deterministic offline mock OpenAI-compatible provider.

Runs a tiny HTTP server (stdlib only) that responds to
POST /v1/chat/completions with a JSON ChatCompletion body.

The response is chosen from a hard-coded table keyed by substring
of the last user message. This is enough for a demo that
captures non-trivial exchanges without ever touching the network.

Usage:
    python3 mock_provider.py --port 9876
    # ... then point dontlie proxy at it:
    DONTLIE_UPSTREAM_BASE_URL=http://127.0.0.1:9876
    python3 -m dontlie proxy --port 8765
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# --- canned responses ---------------------------------------------------------

def _reply_for(prompt: str) -> str:
    p = prompt.lower()
    if "ping" in p:
        return "pong"
    if "capital of france" in p:
        return "Paris"
    if "phi-3" in p or "minimax" in p:
        return "MiniMax is a global AI foundation model company founded in early 2022."
    if "what is 2+2" in p:
        return "4"
    if "summarize" in p:
        return "Don't-Lie is a local-first, signed-receipt vault for LLM prompts and responses."
    if "extract" in p:
        return json.dumps({"title": "Mock extraction", "items": ["a", "b", "c"]})
    return f"mock-ack: {prompt[:80]}"


def _completion(prompt: str, model: str) -> dict:
    return {
        "id": f"mock-{int(time.time() * 1000)}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model or "mock-1",
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": _reply_for(prompt),
                },
                "finish_reason": "stop",
            }
        ],
        "usage": {
            "prompt_tokens": len(prompt.split()),
            "completion_tokens": 4,
            "total_tokens": len(prompt.split()) + 4,
        },
    }


# --- HTTP server --------------------------------------------------------------

class MockHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        sys.stderr.write(f"[mock_provider] {fmt % args}\n")

    def do_POST(self):
        if not self.path.endswith("/chat/completions"):
            self.send_response(404)
            self.end_headers()
            return
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length) if length else b"{}"
        try:
            body = json.loads(raw)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            return
        messages = body.get("messages") or []
        last_user = ""
        for m in reversed(messages):
            if m.get("role") == "user":
                last_user = m.get("content") if isinstance(m.get("content"), str) else json.dumps(m.get("content"))
                break
        model = body.get("model", "mock-1")
        resp = _completion(last_user, model)
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        self.send_response(404)
        self.end_headers()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=9876)
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), MockHandler)
    print(f"mock provider listening on http://127.0.0.1:{args.port}", file=sys.stderr)
    print("  POST /v1/chat/completions  -> canned response", file=sys.stderr)
    print("  GET  /health               -> {status:ok}", file=sys.stderr)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
