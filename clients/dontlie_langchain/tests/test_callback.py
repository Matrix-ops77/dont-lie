"""Tests for the LangChain callback.

These tests rely on a ``FakeGeneration`` stand-in so they don't require
the real ``langchain-core`` package. The callback is built to be
langchain-agnostic: it imports the framework lazily and degrades to a
no-op when missing.
"""

from __future__ import annotations

import importlib
import os
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

_TMP = tempfile.mkdtemp(prefix="dontlie-langchain-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"
os.environ["DONTLIE_REDACTION_POLICY"] = "default"

# Make sure the dontlie package is importable from the repo.
sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

mod = importlib.import_module("dontlie_langchain")
DontlieCallback = mod.DontlieCallback


class FakeMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class FakeGeneration:
    def __init__(self, text: str) -> None:
        self.message = FakeMessage(text)


class FakeResponse:
    def __init__(self, generations: list[FakeGeneration], model_name: str) -> None:
        self.generations = generations
        self.llm_output = {"model_name": model_name}


class LangchainCallbackTest(unittest.TestCase):
    def setUp(self) -> None:
        from dontlie import storage
        with storage.db() as conn:
            conn.executescript(storage.SCHEMA)
            conn.execute("DELETE FROM receipts")
            conn.execute("DELETE FROM key_history")
            conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
        from dontlie import sign as signing
        signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
        for path in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
            path.unlink(missing_ok=True)
        signing.generate()

    def test_callback_writes_receipt(self) -> None:
        cb = DontlieCallback(tags=["test"])
        cb.on_llm_start({}, ["ping"])
        cb.on_llm_end(FakeResponse([FakeGeneration("pong")], "mock-1"))
        from dontlie import storage
        receipts = storage.list_receipts(limit=100)
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0].prompt, "ping")
        self.assertEqual(receipts[0].response, "pong")
        self.assertIn("test", receipts[0].tags)

    def test_callback_redacts_secrets(self) -> None:
        cb = DontlieCallback()
        cb.on_llm_start({}, ["my key is sk-abcdef1234567890abcdef1234567890AB"])
        cb.on_llm_end(FakeResponse([FakeGeneration("ok")], "mock-1"))
        from dontlie import storage
        receipt = storage.list_receipts(limit=100)[0]
        self.assertIn("[REDACTED:OPENAI_API_KEY]", receipt.prompt)

    def test_disabled_redaction_passes_raw(self) -> None:
        prev = os.environ.get("DONTLIE_REDACTION_POLICY")
        os.environ["DONTLIE_REDACTION_POLICY"] = "off"
        try:
            cb = DontlieCallback()
            cb.on_llm_start({}, ["sk-abcdef1234567890abcdef1234567890AB"])
            cb.on_llm_end(FakeResponse([FakeGeneration("ok")], "mock-1"))
            from dontlie import storage
            receipt = storage.list_receipts(limit=100)[0]
            self.assertIn("sk-abcdef1234567890abcdef1234567890AB", receipt.prompt)
        finally:
            if prev is None:
                os.environ.pop("DONTLIE_REDACTION_POLICY", None)
            else:
                os.environ["DONTLIE_REDACTION_POLICY"] = prev


if __name__ == "__main__":
    unittest.main()
