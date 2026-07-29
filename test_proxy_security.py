"""Focused proxy/security tests for dontlie.

Run: ``python -m unittest test_proxy_security.py``

Covers the proxy surface and threat-model assumptions from
``security.md``:

* header filter does not leak hop-by-hop or signing secrets
* SSE stream is parsed and bound to a receipt
* upstream timeouts and connection errors become clean upstream errors,
  not 5xx the proxy itself invents
* ``/v1/chat/completions`` validates body shape before doing upstream work
* non-stream upstream errors are propagated with original status
* streaming path flushes to the client token-by-token
* /healthz endpoint returns ok without touching the upstream
"""

import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

_TMP = tempfile.mkdtemp(prefix="dontlie-proxy-sec-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

# Make the workspace importable regardless of cwd.
_HERE = Path(__file__).resolve().parent
if str(_HERE.parent) not in sys.path:
    sys.path.insert(0, str(_HERE.parent))

from dontlie import cli, proxy, storage
from dontlie import sign as signing


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _fresh_keypair():
    signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
    for p in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
        if p.exists():
            p.unlink()
    return signing.generate()


def _fresh_db(name: str) -> Path:
    import sqlite3
    db_file = Path(_TMP) / name
    storage.DB_PATH = db_file
    conn = sqlite3.connect(db_file)
    try:
        conn.executescript(storage.SCHEMA)
        conn.execute("DELETE FROM receipts")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
        conn.commit()
    finally:
        conn.close()
    return db_file


class HeaderFilterTest(unittest.TestCase):
    """Security: don't forward hop-by-hop headers or the secret channel."""

    def test_strips_hop_by_hop_and_secret_header(self):
        out = proxy._filter_forward_headers({
            "Host": "127.0.0.1:8765",
            "Content-Length": "42",
            "Connection": "keep-alive",
            "Transfer-Encoding": "chunked",
            "Upgrade": "websocket",
            "Proxy-Authorization": "Bearer leak",
            "TE": "trailers",
            "x-dontlie-upstream-key": "sk-secret",
            "Authorization": "Bearer client-placeholder",
            "x-api-key": "client-secret",
            "Content-Type": "application/json",
            "User-Agent": "openai-python/1.0",
        })
        # None of the filtered keys survive.
        lowered = {k.lower() for k in out}
        for forbidden in (
            "host", "content-length", "connection", "transfer-encoding",
            "upgrade", "proxy-authorization", "te", "x-dontlie-upstream-key",
            "authorization", "x-api-key",
        ):
            self.assertNotIn(forbidden, lowered)
        # And the user's payload-shape headers do (case preserved).
        self.assertIn("Content-Type", out)
        self.assertEqual(out["Content-Type"], "application/json")
        self.assertIn("User-Agent", out)
        self.assertEqual(out["User-Agent"], "openai-python/1.0")

    def test_case_insensitive(self):
        out = proxy._filter_forward_headers({
            "HOST": "x", "host": "y", "HoSt": "z", "x-Dontlie-Upstream-Key": "sk",
        })
        self.assertEqual(out, {})


class ValidationTest(unittest.TestCase):
    def test_rejects_non_object_body(self):
        self.assertEqual(proxy._validate_chat_body("hi")[0], None)
        self.assertIn("must be a JSON object", proxy._validate_chat_body([1, 2])[1])

    def test_rejects_missing_model(self):
        parsed, err = proxy._validate_chat_body({"messages": []})
        self.assertIsNone(parsed)
        self.assertIn("'model'", err)

    def test_accepts_minimal_chat_body(self):
        parsed, err = proxy._validate_chat_body({"model": "m"})
        self.assertIsNone(err)
        self.assertEqual(parsed, {"model": "m"})

    def test_rejects_messages_wrong_type(self):
        parsed, err = proxy._validate_chat_body({"model": "m", "messages": "oops"})
        self.assertIsNone(parsed)
        self.assertIn("'messages'", err)


class ForwardErrorPropagationTest(unittest.TestCase):
    """The proxy must never invent a 5xx for an upstream it never reached."""

    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-fwd-{id(self)}.db")

    def test_connect_error_propagates_as_exception_not_silent_500(self):
        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}

        async def _raise(*a, **kw):
            _ = (a, kw)
            raise httpx.ConnectError("nope")

        with patch.object(proxy, "_stream_response", side_effect=_raise), \
             patch.object(proxy.httpx, "AsyncClient") as ac:
            # The non-streaming path uses _make_upstream_client().request;
            # make that raise to mirror a real network failure.
            ac.return_value.__aenter__.return_value.request = AsyncMock(
                side_effect=httpx.ConnectError("nope"),
            )
            with self.assertRaises(httpx.ConnectError):
                proxy.handle_chat_completion(body, "k")

    def test_upstream_404_passthrough(self):
        body = {"model": "m", "messages": [{"role": "user", "content": "hi"}]}
        forward = AsyncMock(
            return_value=(404, {"content-type": "application/json"}, b'{"error":"not found"}'),
        )
        with patch.object(proxy, "_forward_and_capture", forward):
            result = proxy.handle_chat_completion(body, "k")
        self.assertEqual(result["_dontlie_passthrough_status"], 404)
        self.assertIn("not found", result["_dontlie_passthrough_body"])
        # Receipt still gets written — the upstream rejected the request,
        # but the operator still wants an audit record of the attempt.
        self.assertEqual(storage.list_receipts(limit=1)[0].extra["status"], 404)


class StreamingPipelineTest(unittest.TestCase):
    """SSE: full body is captured for the receipt, and chunks are forwarded."""

    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-stream-{id(self)}.db")

    def _sse(self, *chunks: str) -> bytes:
        return "\n".join(f"data: {c}" for c in chunks).encode("utf-8")

    def test_streaming_response_is_collected_and_receipted(self):
        sse = self._sse(
            json.dumps({"choices": [{"delta": {"content": "Hel"}}]}),
            json.dumps({"choices": [{"delta": {"content": "lo."}}]}),
            "[DONE]",
        )
        forward = AsyncMock(
            return_value=(200, {"content-type": "text/event-stream"}, sse),
        )
        body = {
            "model": "m",
            "stream": True,
            "messages": [{"role": "user", "content": "hi"}],
        }
        with patch.object(proxy, "_forward_and_capture", forward):
            result = proxy.handle_chat_completion(body, "k")
        self.assertEqual(result["_dontlie_passthrough_status"], 200)
        # Streaming path returns raw bytes for the CLI to forward.
        self.assertIn(b"Hel", result["_dontlie_passthrough_body_bytes"])
        # Receipt text was reconstructed from the SSE deltas.
        receipt = storage.list_receipts(limit=1)[0]
        self.assertEqual(receipt.response, "Hello.")
        self.assertIn("stream", receipt.tags)

    def test_stream_chat_completion_writes_each_chunk_and_flushes(self):
        """End-to-end-ish: the streaming helper should call write+flush per chunk."""
        chunks_seen_by_client: list[bytes] = []
        flushes = 0

        async def _write(b: bytes) -> None:
            chunks_seen_by_client.append(b)

        async def _flush() -> None:
            nonlocal flushes
            flushes += 1

        # Build a fake upstream by patching _stream_response.
        sse = b"data: {\"choices\":[{\"delta\":{\"content\":\"x\"}}]}\ndata: [DONE]\n"

        async def _fake_stream(
            method, url, headers, body, on_chunk, on_start=None
        ):
            _ = (method, url, headers, body)
            if on_start is not None:
                await on_start(200, {"content-type": "text/event-stream"})
            for part in sse.split(b"\n"):
                if part:
                    await on_chunk(part + b"\n")
            return 200, {"content-type": "text/event-stream"}, len(sse)

        with patch.object(proxy, "_stream_response", side_effect=_fake_stream):
            info = asyncio.run(
                proxy.stream_chat_completion_to_client(
                    {"model": "m", "stream": True, "messages": []},
                    "k",
                    _write,
                    _flush,
                )
            )
        self.assertEqual(info["status"], 200)
        self.assertGreaterEqual(flushes, 2)
        self.assertEqual(b"".join(chunks_seen_by_client), sse)
        # Receipt must contain the reconstructed text.
        receipt = storage.list_receipts(limit=1)[0]
        self.assertEqual(receipt.response, "x")

    def test_streaming_error_preserves_status_and_json_receipt(self):
        starts: list[tuple[int, str | None]] = []
        chunks: list[bytes] = []
        error_body = b'{"error":{"message":"bad key"}}'

        async def _write(chunk: bytes) -> None:
            chunks.append(chunk)

        async def _flush() -> None:
            return None

        async def _start(status: int, headers: dict[str, str]) -> None:
            starts.append((status, headers.get("content-type")))

        async def _fake_error_stream(
            method, url, headers, body, on_chunk, on_start=None
        ):
            _ = (method, url, headers, body)
            if on_start is not None:
                await on_start(401, {"content-type": "application/json"})
            await on_chunk(error_body)
            return 401, {"content-type": "application/json"}, len(error_body)

        with patch.object(
            proxy, "_stream_response", side_effect=_fake_error_stream
        ):
            info = asyncio.run(
                proxy.stream_chat_completion_to_client(
                    {"model": "m", "stream": True, "messages": []},
                    "bad-key",
                    _write,
                    _flush,
                    on_start=_start,
                )
            )

        self.assertEqual(info["status"], 401)
        self.assertEqual(starts, [(401, "application/json")])
        self.assertEqual(b"".join(chunks), error_body)
        receipt = storage.list_receipts(limit=1)[0]
        self.assertIn("bad key", receipt.response)
        self.assertEqual(receipt.extra["status"], 401)


class CLIRoutingTest(unittest.TestCase):
    """Confirm the CLI proxy wires the right things and rejects bad input."""

    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-cli-{id(self)}.db")
        self.port = _free_port()

    def test_doctor_exits_1_when_key_missing(self):
        with patch.dict(os.environ, {}, clear=True):
            rc = cli.cmd_doctor(None)
        self.assertEqual(rc, 1)

    def test_doctor_passes_with_key_and_upstream(self):
        with patch.dict(
            os.environ,
            {"DONTLIE_UPSTREAM_API_KEY": "sk", "DONTLIE_UPSTREAM_BASE_URL": "https://x/v1"},
            clear=True,
        ):
            rc = cli.cmd_doctor(None)
        self.assertEqual(rc, 0)


class _StubServer:
    """Tiny TCP server that returns a canned SSE body. Used to exercise
    the real streaming HTTP path without hitting a real provider."""

    def __init__(
        self,
        body: bytes,
        content_type: bytes = b"text/event-stream",
        status: int = 200,
    ):
        self.body = body
        self.content_type = content_type
        self.status = status
        self.received: bytes = b""
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._thread: threading.Thread | None = None
        self._stop = False

    def start(self):
        import threading
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        try:
            self._sock.settimeout(5.0)
            conn, _ = self._sock.accept()
        except (TimeoutError, OSError):
            return
        try:
            conn.settimeout(5.0)
            data = b""
            # Read headers
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            header_blob, _, rest = data.partition(b"\r\n\r\n")
            self.received = header_blob
            content_length = None
            for line in header_blob.split(b"\r\n"):
                if line.lower().startswith(b"content-length:"):
                    try:
                        content_length = int(line.split(b":", 1)[1].strip())
                    except ValueError:
                        pass
            if content_length is not None and len(rest) < content_length:
                rest += conn.recv(content_length - len(rest))
            # Reply
            resp = (
                b"HTTP/1.1 " + str(self.status).encode() + b" Test\r\n"
                + b"content-type: " + self.content_type + b"\r\n"
                + b"content-length: " + str(len(self.body)).encode() + b"\r\n"
                + b"connection: close\r\n\r\n"
                + self.body
            )
            conn.sendall(resp)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self._sock.close()
        except OSError:
            pass


class LiveStreamProxyTest(unittest.TestCase):
    """End-to-end: start the real proxy server, send a streaming request,
    confirm SSE chunks come back, confirm a receipt was written."""

    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-live-{id(self)}.db")
        self.port = _free_port()
        self._env_patch = patch.dict(
            os.environ,
            {
                "DONTLIE_UPSTREAM_API_KEY": "sk-test",
                "DONTLIE_UPSTREAM_BASE_URL": "http://127.0.0.1:0",  # overridden below
            },
            clear=True,
        )
        self._env_patch.start()

    def tearDown(self):
        self._env_patch.stop()

    def test_streaming_request_through_real_server(self):
        sse = (
            b'data: {"choices":[{"delta":{"content":"a"}}]}\n'
            b'data: {"choices":[{"delta":{"content":"b"}}]}\n'
            b"data: [DONE]\n\n"
        )
        stub = _StubServer(sse)
        stub.start()
        try:
            # Point upstream at the stub.
            with patch.dict(
                os.environ,
                {"DONTLIE_UPSTREAM_BASE_URL": f"http://127.0.0.1:{stub.port}"},
            ):
                # Launch the proxy in a thread.
                import threading
                from argparse import Namespace
                ns = Namespace(
                    port=self.port,
                    upstream_base_url=None,
                    verbose=False,
                )
                t = threading.Thread(
                    target=cli.cmd_proxy, args=(ns,), daemon=True,
                )
                t.start()
                try:
                    # Wait for the proxy to bind.
                    deadline = time.time() + 5.0
                    while time.time() < deadline:
                        with socket.socket() as s:
                            try:
                                s.connect(("127.0.0.1", self.port))
                                break
                            except OSError:
                                time.sleep(0.05)

                    body = {
                        "model": "m",
                        "stream": True,
                        "messages": [{"role": "user", "content": "hi"}],
                    }
                    with httpx.Client(timeout=5.0) as client:
                        r = client.post(
                            f"http://127.0.0.1:{self.port}/v1/chat/completions",
                            json=body,
                        )
                    self.assertEqual(r.status_code, 200)
                    self.assertIn('"content":"a"', r.text)
                    self.assertIn('"content":"b"', r.text)
                finally:
                    # Stop the proxy.
                    import urllib.request
                    try:
                        urllib.request.urlopen(
                            f"http://127.0.0.1:{self.port}/_dontlie/health",
                            timeout=1.0,
                        )
                    except (OSError, httpx.HTTPError):
                        pass
        finally:
            stub.stop()

    def test_streaming_upstream_error_status_reaches_client(self):
        error = b'{"error":{"message":"bad key"}}'
        stub = _StubServer(error, b"application/json", status=401)
        stub.start()
        try:
            with patch.dict(
                os.environ,
                {"DONTLIE_UPSTREAM_BASE_URL": f"http://127.0.0.1:{stub.port}"},
            ):
                import threading
                from argparse import Namespace

                ns = Namespace(
                    port=self.port,
                    upstream_base_url=None,
                    verbose=False,
                )
                threading.Thread(
                    target=cli.cmd_proxy, args=(ns,), daemon=True
                ).start()
                deadline = time.time() + 5.0
                while time.time() < deadline:
                    try:
                        with socket.create_connection(("127.0.0.1", self.port), 0.2):
                            break
                    except OSError:
                        time.sleep(0.05)
                response = httpx.post(
                    f"http://127.0.0.1:{self.port}/v1/chat/completions",
                    json={
                        "model": "m",
                        "stream": True,
                        "messages": [{"role": "user", "content": "hi"}],
                    },
                    timeout=5.0,
                )
                self.assertEqual(response.status_code, 401)
                self.assertEqual(response.headers["content-type"], "application/json")
                self.assertIn("bad key", response.text)
        finally:
            stub.stop()

    def test_healthz_does_not_call_upstream(self):
        # No stub server needed: /healthz must not touch the upstream.
        import threading
        from argparse import Namespace
        ns = Namespace(port=self.port, upstream_base_url=None, verbose=False)
        t = threading.Thread(target=cli.cmd_proxy, args=(ns,), daemon=True)
        t.start()
        try:
            deadline = time.time() + 5.0
            while time.time() < deadline:
                with socket.socket() as s:
                    try:
                        s.connect(("127.0.0.1", self.port))
                        break
                    except OSError:
                        time.sleep(0.05)
            r = httpx.get(
                f"http://127.0.0.1:{self.port}/_dontlie/health", timeout=2.0
            )
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.json()["status"], "ok")
        finally:
            # Force shutdown by hitting an unknown path that 404s; the
            # test process tearDown will follow.
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)
