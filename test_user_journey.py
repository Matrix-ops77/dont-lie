"""Tests for the fresh-user experience.

These exercise the exact commands a real user runs after
`pipx install dontlie`:

    dontlie proxy --mock --port <port>
    # in another shell, use any openai-compatible client
    dontlie verify
    dontlie witness-attest <id>

The goal is to catch regressions in the "actually works on a
clean machine" path, separate from the unit tests of internal
modules.
"""
from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from test_helpers import dontlie_cmd, with_dontlie_env

REPO = Path(__file__).resolve().parent
sys.path.insert(0, str(REPO))


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for(url: str, timeout: float = 5.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as r:
                if 200 <= r.status < 300:
                    return True
        except Exception:
            time.sleep(0.1)
    return False


class MockProxyUserJourneyTest(unittest.TestCase):
    """`dontlie proxy --mock` lets a fresh user try the product
    end-to-end without an API key. This is the entry point."""

    def setUp(self) -> None:
        self._tmp = Path(__file__).resolve().parent / "_user_journey_workdir"
        self._tmp.mkdir(exist_ok=True)
        self.port = _free_port()

    def _start_proxy(self, *extra: str) -> subprocess.Popen:
        env = with_dontlie_env()
        # Use a dedicated workdir so the test never touches the
        # developer's real vault.
        env["DONTLIE_KEY_DIR"] = str(self._tmp / "keys")
        env["DONTLIE_DB"] = str(self._tmp / "vault.db")
        env["DONTLIE_NO_WAL"] = "1"
        # Ensure no real upstream key so we can confirm --mock works
        # without one.
        for k in ("DONTLIE_UPSTREAM_API_KEY", "DONTLIE_UPSTREAM_BASE_URL",
                  "OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
            env.pop(k, None)
        return subprocess.Popen(
            dontlie_cmd("proxy", "--mock", "--port", str(self.port), *extra),
            env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )

    def test_proxy_mock_starts_without_api_key(self) -> None:
        proc = self._start_proxy()
        try:
            self.assertTrue(
                _wait_for(f"http://127.0.0.1:{self.port}/_dontlie/health"),
                msg="proxy did not start in time",
            )
            # /healthz responds and reports the version
            with urllib.request.urlopen(
                f"http://127.0.0.1:{self.port}/_dontlie/health", timeout=3
            ) as r:
                payload = json.loads(r.read())
            self.assertEqual(payload["status"], "ok")
            self.assertIn("version", payload)
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    def test_proxy_mock_routes_chat_completion(self) -> None:
        proc = self._start_proxy()
        try:
            self.assertTrue(
                _wait_for(f"http://127.0.0.1:{self.port}/_dontlie/health"),
            )
            # Give the in-process mock provider a beat to bind. The
            # mock is started in a background thread, so even after
            # the proxy's /healthz is up the upstream socket might
            # not be ready on the first request.
            time.sleep(0.5)
            # Make a real call. The mock returns a canned response.
            body = json.dumps({
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "ping"}],
            }).encode("utf-8")
            req = urllib.request.Request(
                f"http://127.0.0.1:{self.port}/v1/chat/completions",
                data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as r:
                payload = json.loads(r.read())
            self.assertEqual(payload["choices"][0]["message"]["content"], "pong")
            # A receipt was written to the test vault.
            import sqlite3
            with sqlite3.connect(env_db(self._tmp)) as conn:
                count = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
            self.assertGreaterEqual(count, 1, "no receipt was created")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


def env_db(tmp: Path) -> str:
    return str(tmp / "vault.db")


class MockProviderImportTest(unittest.TestCase):
    """The mock provider is an importable module so the proxy --mock
    mode works for PyPI users (no script on disk)."""

    def test_mock_provider_imports(self) -> None:
        from dontlie import mock_provider
        self.assertTrue(hasattr(mock_provider, "MockHandler"))
        self.assertTrue(hasattr(mock_provider, "MockServer"))
        self.assertTrue(callable(mock_provider.start_mock_server))
        self.assertTrue(callable(mock_provider.stop_mock_server))

    def test_mock_server_binds_to_free_port(self) -> None:
        from dontlie import mock_provider
        srv = mock_provider.start_mock_server(port=0)
        try:
            self.assertGreater(srv.port, 0)
            # Health check
            with urllib.request.urlopen(
                f"{srv.base_url}/health", timeout=2
            ) as r:
                self.assertEqual(r.status, 200)
        finally:
            srv.stop()

    def test_mock_server_serves_chat_completion(self) -> None:
        from dontlie import mock_provider
        srv = mock_provider.start_mock_server(port=0)
        try:
            body = json.dumps({
                "model": "mock-1",
                "messages": [{"role": "user", "content": "capital of france"}],
            }).encode("utf-8")
            req = urllib.request.Request(
                f"{srv.base_url}/v1/chat/completions",
                data=body, method="POST",
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=2) as r:
                payload = json.loads(r.read())
            self.assertEqual(payload["choices"][0]["message"]["content"], "Paris")
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
