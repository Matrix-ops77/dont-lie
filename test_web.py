"""Smoke tests for the web UI.

Run: python3 -m unittest test_web
"""
import json
import os
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

from dontlie import sign as signing
from dontlie import storage
from dontlie.web import _Handler  # type: ignore[import-not-found]


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class WebServerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls._tmp = Path(tempfile.mkdtemp(prefix="dontlie-web-test-"))
        cls._keys = cls._tmp / "keys"
        cls._keys.mkdir()
        cls._db = cls._tmp / "vault.db"
        os.environ["DONTLIE_KEY_DIR"] = str(cls._keys)
        os.environ["DONTLIE_DB"] = str(cls._db)
        os.environ["DONTLIE_NO_WAL"] = "1"
        # Reset modules
        import importlib
        importlib.reload(signing)
        signing.KEY_DIR = cls._keys
        signing.PRIVATE_FILE = cls._keys / "dontlie.key"
        signing.PUBLIC_FILE = cls._keys / "dontlie.pub"
        signing.KEY_ID_FILE = cls._keys / "key_id"
        signing.generate()
        importlib.reload(storage)
        storage.init()
        # Add a couple of receipts
        storage.append(model="gpt-4o-mini", prompt="ping", response="pong")
        storage.append(model="gpt-4o-mini", prompt="hello", response="hi")
        # Start the server
        from http.server import ThreadingHTTPServer
        cls.port = _free_port()
        cls.server = ThreadingHTTPServer(("127.0.0.1", cls.port), _Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        # Give it a beat
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        import shutil
        shutil.rmtree(cls._tmp, ignore_errors=True)

    def _get(self, path: str) -> tuple[int, str, bytes]:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read()
            return resp.status, resp.headers.get("Content-Type", ""), body

    def test_dashboard(self) -> None:
        status, ct, body = self._get("/")
        self.assertEqual(status, 200)
        self.assertIn("text/html", ct)
        self.assertIn(b"Don't-Lie", body)
        self.assertIn(b"trust", body.lower())  # trust card is in the dashboard

    def test_receipt_detail(self) -> None:
        status, _ct, body = self._get("/receipt/1")
        self.assertEqual(status, 200)
        self.assertIn(b"Receipt #1", body)
        self.assertIn(b"gpt-4o-mini", body)

    def test_receipt_not_found(self) -> None:
        status, _ct, body = self._get("/receipt/99999")
        self.assertEqual(status, 200)
        self.assertIn(b"not found", body.lower())

    def test_search_page(self) -> None:
        status, _ct, body = self._get("/search?q=ping")
        self.assertEqual(status, 200)
        self.assertIn(b"ping", body)

    def test_verify_page(self) -> None:
        status, _ct, body = self._get("/verify")
        self.assertEqual(status, 200)
        self.assertIn(b"VERIFIED", body.upper())

    def test_api_stats(self) -> None:
        status, ct, body = self._get("/api/stats")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        d = json.loads(body)
        self.assertIn("total_receipts", d)
        self.assertEqual(d["total_receipts"], 2)
        self.assertIn("ok", d)

    def test_api_verify(self) -> None:
        status, _ct, body = self._get("/api/verify")
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(d["ok_count"], 2)
        self.assertEqual(d["bad_count"], 0)
        self.assertEqual(d["total"], 2)

    def test_api_receipts_list(self) -> None:
        status, _ct, body = self._get("/api/receipts")
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(d["total"], 2)
        self.assertEqual(len(d["receipts"]), 2)
        self.assertIn("payload_sha256", d["receipts"][0])

    def test_api_receipts_detail(self) -> None:
        status, _ct, body = self._get("/api/receipts/1")
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertEqual(d["id"], 1)
        self.assertEqual(d["model"], "gpt-4o-mini")
        self.assertIn("payload_sha256", d)

    def test_api_receipts_not_found(self) -> None:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/receipts/99999")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)
            return
        self.fail("expected 404")

    def test_export_bundle(self) -> None:
        status, ct, body = self._get("/export")
        self.assertEqual(status, 200)
        self.assertIn("application/json", ct)
        d = json.loads(body)
        self.assertEqual(len(d["receipts"]), 2)
        self.assertIn("public_keys", d)
        self.assertIn("version", d)

    def test_404(self) -> None:
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/nope")
        try:
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)
            return
        self.fail("expected 404")


if __name__ == "__main__":
    unittest.main()
