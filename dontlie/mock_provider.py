"""Deterministic offline mock OpenAI-compatible provider.

Importable as ``dontlie.mock_provider`` so that ``dontlie proxy --mock``
can spin up a local fake provider in-process and route signed receipts
through it without any external service.

Also runnable as a script for source-checkout users who want to point
``dontlie proxy`` at a mock manually:

    python3 -m dontlie.mock_provider --port 9876
    DONTLIE_UPSTREAM_BASE_URL=http://127.0.0.1:9876 \\
        dontlie proxy --port 8080
"""
from __future__ import annotations

import argparse
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

__all__ = [
    "MockHandler",
    "MockServer",
    "start_mock_server",
    "stop_mock_server",
    "DEFAULT_PORT",
]

DEFAULT_PORT = 9876


# --- canned responses ---------------------------------------------------------


def _reply_for(prompt: str) -> str:
    p = (prompt or "").lower()
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
    return f"mock-ack: {(prompt or '')[:80]}"


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
            "prompt_tokens": len((prompt or "").split()),
            "completion_tokens": 4,
            "total_tokens": len((prompt or "").split()) + 4,
        },
    }


# --- HTTP handler --------------------------------------------------------------


class MockHandler(BaseHTTPRequestHandler):
    """Stdlib HTTP handler that mimics the OpenAI chat-completions endpoint."""

    def log_message(self, fmt, *args):  # noqa: A003
        sys.stderr.write(f"[mock_provider] {fmt % args}\n")

    def do_POST(self):  # noqa: N802
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
                content = m.get("content")
                last_user = content if isinstance(content, str) else json.dumps(content)
                break
        model = body.get("model", "mock-1")
        resp = _completion(last_user, model)
        payload = json.dumps(resp).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802
        if self.path == "/health":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            return
        self.send_response(404)
        self.end_headers()


# --- Server lifecycle ---------------------------------------------------------


class MockServer:
    """Wrapper around ``ThreadingHTTPServer`` for in-process use.

    The proxy's ``--mock`` mode creates one of these on a free localhost
    port and points the proxy at it. ``stop()`` is safe to call multiple
    times.
    """

    def __init__(self, port: int = 0) -> None:
        self._port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    @property
    def port(self) -> int:
        if self._server is None:
            return self._port
        return self._server.server_address[1]

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def start(self) -> None:
        self._server = ThreadingHTTPServer(("127.0.0.1", self._port), MockHandler)
        self._thread = threading.Thread(
            target=self._server.serve_forever,
            name="dontlie-mock-provider",
            daemon=True,
        )
        self._thread.start()
        sys.stderr.write(
            f"[dontlie-mock] listening on {self.base_url}/v1/chat/completions\n"
        )

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None


def start_mock_server(port: int = 0) -> MockServer:
    """Start a mock provider and return the server object.

    ``port=0`` lets the OS pick a free port — recommended for
    ``dontlie proxy --mock`` so multiple invocations don't collide.
    """
    srv = MockServer(port=port)
    srv.start()
    return srv


def stop_mock_server(srv: MockServer) -> None:
    srv.stop()


# --- CLI entry point ----------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(
        prog="dontlie-mock-provider",
        description=(
            "Deterministic mock OpenAI-compatible provider for testing "
            "dontlie proxy. Use --port 0 to let the OS pick a free port."
        ),
    )
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="port to bind (0 = pick a free port)")
    args = ap.parse_args()
    srv = MockServer(port=args.port)
    srv.start()
    try:
        # Block forever; the parent process (or user) will SIGINT us.
        if srv._thread is not None:
            srv._thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
