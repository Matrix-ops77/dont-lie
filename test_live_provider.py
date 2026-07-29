"""Live-network integration tests against the real MiniMax provider.

These tests are skipped unless the worktree key file is reachable. They
exercise both the OpenAI-compatible and the Anthropic-compatible
endpoints of the real provider, confirming that Don't-Lie's
`AnthropicMessagesAdapter` works end-to-end on a real network and not
only on synthetic fixtures.
"""

from __future__ import annotations

import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

import httpx


def _worktree_key() -> str | None:
    """Load the worktree key. Skip if not present."""
    candidates = [
        Path.home() / ".pi" / "agent" / "auth.json",
    ]
    for c in candidates:
        if not c.exists():
            continue
        try:
            data = json.loads(c.read_text())
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        key = data.get("minimax", {}).get("key")
        if key:
            return key
    return None


KEY = _worktree_key()
SKIP_REASON = None if KEY else "no real MiniMax key reachable"
OPENAI_BASE = "https://api.minimax.io"
ANTHROPIC_BASE = "https://api.minimax.io/anthropic"


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@unittest.skipIf(SKIP_REASON, SKIP_REASON or "")
class TestRealOpenAIProvider(unittest.TestCase):
    def test_models_endpoint(self) -> None:
        r = httpx.get(
            f"{OPENAI_BASE}/v1/models",
            headers={"Authorization": f"Bearer {KEY}"},
            timeout=15,
        )
        self.assertEqual(r.status_code, 200)
        ids = {m["id"] for m in r.json().get("data", [])}
        self.assertIn("MiniMax-M3", ids)
        self.assertIn("MiniMax-M2.5-highspeed", ids)

    def test_chat_completions_live(self) -> None:
        r = httpx.post(
            f"{OPENAI_BASE}/v1/chat/completions",
            headers={"Authorization": f"Bearer {KEY}"},
            json={
                "model": "MiniMax-M3",
                "messages": [
                    {"role": "user", "content": "Reply only with the word OK."}
                ],
                "max_tokens": 32,
                "stream": False,
            },
            timeout=30,
        )
        self.assertEqual(r.status_code, 200)
        content = r.json()["choices"][0]["message"]["content"]
        self.assertTrue(len(content) > 0)


@unittest.skipIf(SKIP_REASON, SKIP_REASON or "")
class TestRealAnthropicProvider(unittest.TestCase):
    def test_messages_endpoint_live(self) -> None:
        r = httpx.post(
            f"{ANTHROPIC_BASE}/v1/messages",
            headers={
                "x-api-key": KEY,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "MiniMax-M3",
                "max_tokens": 32,
                "system": "You are terse.",
                "messages": [
                    {"role": "user", "content": "Reply with exactly: OK."}
                ],
            },
            timeout=30,
        )
        self.assertEqual(r.status_code, 200)
        body = r.json()
        self.assertEqual(body.get("type"), "message")
        self.assertEqual(body.get("model"), "MiniMax-M3")
        self.assertGreater(len(body.get("content", [])), 0)

    def test_messages_endpoint_with_bearer_header(self) -> None:
        r = httpx.post(
            f"{ANTHROPIC_BASE}/v1/messages",
            headers={
                "Authorization": f"Bearer {KEY}",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "MiniMax-M3",
                "max_tokens": 16,
                "messages": [
                    {"role": "user", "content": "ping"}
                ],
            },
            timeout=30,
        )
        self.assertEqual(r.status_code, 200)


@unittest.skipIf(SKIP_REASON, SKIP_REASON or "")
class TestDontlieProxyAnthropicLive(unittest.TestCase):
    """Run the real Anthropic-compatible path through the actual proxy."""

    def setUp(self) -> None:
        self.workdir = Path(tempfile.mkdtemp(prefix="dontlie-live-anthropic-"))
        self.port = _free_port()
        env = os.environ.copy()
        env.update(
            {
                "DONTLIE_DB": str(self.workdir / "vault.db"),
                "DONTLIE_KEY_DIR": str(self.workdir / "keys"),
                "DONTLIE_NO_WAL": "1",
                "DONTLIE_UPSTREAM_API_KEY": KEY,
                "DONTLIE_UPSTREAM_BASE_URL": OPENAI_BASE,
                "OPENAI_BASE_URL": f"http://127.0.0.1:{self.port}/v1",
                "OPENAI_API_KEY": "dontlie-local",
            }
        )
        subprocess.run(
            [sys.executable, "-m", "dontlie", "gen-key"],
            env=env,
            cwd=".",
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        log = self.workdir / "proxy.log"
        self._proc = subprocess.Popen(
            [
                sys.executable, "-m", "dontlie", "proxy",
                "--port", str(self.port),
                "--protocol", "anthropic",
                "--upstream-path", "/anthropic/v1/messages",
                "--auth-header", "x-api-key",
                "--anthropic-version", "2023-06-01",
            ],
            env=env,
            cwd=".",
            stdout=log.open("wb"),
            stderr=subprocess.STDOUT,
        )
        deadline = time.time() + 10
        while time.time() < deadline:
            if self._proc.poll() is not None:
                raise RuntimeError(log.read_text())
            try:
                if (
                    httpx.get(
                        f"http://127.0.0.1:{self.port}/_dontlie/health",
                        timeout=0.5,
                    ).status_code
                    == 200
                ):
                    return
            except httpx.HTTPError:
                time.sleep(0.1)
        raise RuntimeError("proxy did not become ready")

    def tearDown(self) -> None:
        self._proc.terminate()
        try:
            self._proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self._proc.kill()

    def test_proxy_anthropic_path(self) -> None:
        body = {
            "model": "MiniMax-M3",
            "max_tokens": 64,
            "system": "You are terse.",
            "messages": [
                {
                    "role": "user",
                    "content": (
                        "Count from one to three and present each number on its "
                        "own line. Do not include any other text."
                    ),
                }
            ],
        }
        r = httpx.post(
            f"http://127.0.0.1:{self.port}/v1/messages",
            headers={
                "x-api-key": "dontlie-local",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json=body,
            timeout=30,
        )
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json().get("type"), "message")
        text = "".join(
            b.get("text", "")
            for b in r.json().get("content", [])
            if b.get("type") == "text"
        )
        self.assertIn("1", text)
        self.assertIn("2", text)
        self.assertIn("3", text)


if __name__ == "__main__":
    unittest.main(verbosity=2)
