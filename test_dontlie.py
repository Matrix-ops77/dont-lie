"""stdlib-only test suite for dontlie. Run: python -m unittest test_dontlie.py"""

import base64
import hashlib
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

_TMP = tempfile.mkdtemp(prefix="dontlie-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

from dontlie import (
    proxy,
    storage,
)
from dontlie import sign as signing


def _fresh_keypair():
    signing.KEY_DIR.mkdir(parents=True, exist_ok=True)
    for p in (signing.PRIVATE_FILE, signing.PUBLIC_FILE, signing.KEY_ID_FILE):
        if p.exists():
            p.unlink()
    return signing.generate()


def _fresh_db(name: str) -> Path:
    db_file = Path(_TMP) / name
    storage.DB_PATH = db_file
    # Initialize schema (no WAL — DONTLIE_NO_WAL is set), wipe any rows
    # and reset autoincrement so each test starts at id=1.
    conn = sqlite3.connect(db_file)
    try:
        conn.executescript(storage.SCHEMA)
        conn.execute("DELETE FROM receipts")
        conn.execute("DELETE FROM sqlite_sequence WHERE name='receipts'")
        conn.commit()
    finally:
        conn.close()
    return db_file


class KeySignVerifyTest(unittest.TestCase):
    def setUp(self):
        _fresh_keypair()

    def test_keygen_and_sign_verify_roundtrip(self):
        kp = signing.load()
        msg = b"hello dontlie"
        sig = signing.sign_bytes(kp, msg)
        self.assertTrue(signing.verify_bytes(kp.public, msg, sig))
        self.assertFalse(signing.verify_bytes(kp.public, msg + b"x", sig))

    def test_load_falls_back_to_keychain_when_file_missing(self):
        key = signing.load()
        private_pem = signing.PRIVATE_FILE.read_bytes()
        signing.PRIVATE_FILE.unlink()
        with patch.object(signing, "_keychain_get", return_value=private_pem):
            restored = signing.load()
        self.assertEqual(restored.key_id, key.key_id)
        self.assertTrue(
            signing.verify_bytes(
                restored.public,
                b"x",
                signing.sign_bytes(restored, b"x"),
            )
        )

    def test_persisted_key_loads_and_signs(self):
        kp1 = signing.load()
        msg = b"persisted"
        sig = signing.sign_bytes(kp1, msg)
        kp2 = signing.load()
        self.assertEqual(kp1.key_id, kp2.key_id)
        self.assertTrue(signing.verify_bytes(kp2.public, msg, sig))


class ReceiptChainTest(unittest.TestCase):
    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-{id(self)}.db")

    def test_append_stores_signed_receipt(self):
        r = storage.append(model="gpt-4o-mini", prompt="hi", response="hello")
        self.assertEqual(r.id, 1)
        self.assertIsNone(r.parent_id)
        self.assertEqual(r.key_id, signing.load().key_id)
        self.assertTrue(len(r.signature) > 32)
        ok, bad = storage.verify_chain()
        self.assertEqual(bad, 0)
        self.assertEqual(ok, 1)

    def test_get_receipt_returns_complete_record(self):
        receipt = storage.append(model="m", prompt="full request", response="full response")
        found = storage.get_receipt(receipt.id)
        self.assertIsNotNone(found)
        self.assertEqual(found.response, "full response")
        self.assertIsNone(storage.get_receipt(99999))

    def test_chain_links_parent_ids(self):
        a = storage.append(model="m", prompt="p1", response="r1")
        b = storage.append(model="m", prompt="p2", response="r2")
        c = storage.append(model="m", prompt="p3", response="r3")
        self.assertIsNone(a.parent_id)
        self.assertEqual(b.parent_id, 1)
        self.assertEqual(c.parent_id, 2)

    def test_tampered_response_breaks_verification(self):
        storage.append(model="m", prompt="p", response="original")
        conn = sqlite3.connect(storage.DB_PATH)
        try:
            conn.execute("UPDATE receipts SET response = ? WHERE id = 1", ("TAMPERED",))
            conn.commit()
        finally:
            conn.close()
        ok, bad = storage.verify_chain()
        self.assertEqual(ok, 0)
        self.assertEqual(bad, 1)

    def test_canonical_messages_binds_model(self):
        # Same messages, different model → different canonical bytes.
        body_a = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
        body_b = {"model": "claude-fable-5", "messages": [{"role": "user", "content": "hi"}]}
        self.assertNotEqual(proxy._canonical_messages(body_a), proxy._canonical_messages(body_b))

    def test_canonical_messages_binds_full_history(self):
        # Swapping an earlier turn must change the canonical — a verifier
        # using only the trailing user message would miss this.
        baseline = {"model": "m", "messages": [
            {"role": "system", "content": "You are terse."},
            {"role": "user", "content": "hi"},
        ]}
        swapped = {"model": "m", "messages": [
            {"role": "system", "content": "You are verbose."},
            {"role": "user", "content": "hi"},
        ]}
        self.assertNotEqual(proxy._canonical_messages(baseline), proxy._canonical_messages(swapped))

    def test_canonical_request_binds_generation_parameters_and_tools(self):
        base = {
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "temperature": 0,
            "tools": [],
        }
        changed = {**base, "temperature": 1}
        self.assertNotEqual(
            proxy._canonical_messages(base), proxy._canonical_messages(changed)
        )

    def test_model_swap_after_signing_fails_verification(self):
        # Receipt is signed with model A; if an attacker rewrites the row's
        # model column to B (DB write access), the canonical hash diverges
        # and verification fails.
        body = {"model": "gpt-4o-mini", "messages": [{"role": "user", "content": "hi"}]}
        with patch.object(proxy, "_forward_and_capture",
                          AsyncMock(return_value=(200, {"content-type": "application/json"},
                                                  b'{"choices":[{"message":{"content":"hi"}}]}'))):
            proxy.handle_chat_completion(body, "k")
        # Tamper the model column.
        conn = sqlite3.connect(storage.DB_PATH)
        try:
            conn.execute("UPDATE receipts SET model = ? WHERE id = 1", ("claude-fable-5",))
            conn.commit()
        finally:
            conn.close()
        ok, bad = storage.verify_chain()
        self.assertEqual(ok, 0)
        self.assertEqual(bad, 1)

    def test_revoked_key_fails_verification(self):
        storage.append(model="m", prompt="p", response="r")
        key_id = signing.load().key_id
        # Sanity: chain verifies while key is active.
        self.assertEqual(storage.verify_chain(), (1, 0))
        storage.revoke_key(key_id)
        self.assertEqual(storage.verify_chain(), (0, 1))
        # Idempotent re-revoke.
        storage.revoke_key(key_id)
        self.assertEqual(storage.verify_chain(), (0, 1))

    def test_unrelated_revocation_does_not_block_other_keys(self):
        # Revoking a key_id that no receipt used must not turn good rows bad.
        storage.append(model="m", prompt="p", response="r")
        storage.revoke_key("deadbeefdeadbeef")
        self.assertEqual(storage.verify_chain(), (1, 0))


class ProxyTest(unittest.TestCase):
    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-proxy-{id(self)}.db")

    def test_resolve_upstream_uses_dedicated_env(self):
        with patch.dict(
            os.environ,
            {"DONTLIE_UPSTREAM_BASE_URL": "https://api.minimax.io/v1/"},
            clear=True,
        ):
            self.assertEqual(
                proxy.resolve_upstream_base_url(),
                "https://api.minimax.io/v1",
            )

    def test_resolve_upstream_ignores_client_openai_base_url(self):
        with patch.dict(
            os.environ,
            {"OPENAI_BASE_URL": "http://127.0.0.1:8765/v1"},
            clear=True,
        ):
            self.assertEqual(
                proxy.resolve_upstream_base_url(),
                proxy.DEFAULT_UPSTREAM_BASE_URL,
            )

    def test_upstream_url_normalizes_v1_once(self):
        self.assertEqual(
            proxy._upstream_url(
                "https://api.minimax.io/v1", "/v1/chat/completions"
            ),
            "https://api.minimax.io/v1/chat/completions",
        )
        self.assertEqual(
            proxy._upstream_url(
                "https://api.minimax.io", "/v1/chat/completions"
            ),
            "https://api.minimax.io/v1/chat/completions",
        )

    def test_handle_forwards_explicit_upstream_and_logs_full_context(self):
        body = {
            "model": "MiniMax-M3",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Say hello."},
            ],
        }
        upstream_body = json.dumps(
            {"choices": [{"message": {"content": "Hello."}}]}
        ).encode()
        forward = AsyncMock(
            return_value=(200, {"content-type": "application/json"}, upstream_body)
        )

        with patch.object(proxy, "_forward_and_capture", forward):
            result = proxy.handle_chat_completion(
                body,
                "provider-key",
                upstream_base_url="https://api.minimax.io/v1",
            )

        self.assertEqual(result["choices"][0]["message"]["content"], "Hello.")
        self.assertEqual(
            forward.await_args.kwargs["upstream_base_url"],
            "https://api.minimax.io/v1",
        )
        receipt = storage.list_receipts(limit=1)[0]
        self.assertEqual(receipt.prompt, proxy._canonical_messages(body))
        self.assertEqual(receipt.response, "Hello.")
        self.assertEqual(receipt.extra["status"], 200)
        self.assertEqual(
            receipt.extra["response_sha256"],
            hashlib.sha256(upstream_body).hexdigest(),
        )
        self.assertEqual(
            base64.b64decode(receipt.extra["response_raw_b64"]), upstream_body
        )

    def test_upstream_error_status_is_preserved(self):
        error_body = b'{"error":{"message":"Incorrect API key"}}'
        forward = AsyncMock(
            return_value=(
                401,
                {"content-type": "application/json"},
                error_body,
            )
        )
        body = {
            "model": "MiniMax-M3",
            "messages": [{"role": "user", "content": "hello"}],
        }

        with patch.object(proxy, "_forward_and_capture", forward):
            result = proxy.handle_chat_completion(body, "bad-key")

        self.assertEqual(result["_dontlie_passthrough_status"], 401)
        self.assertEqual(
            result["_dontlie_passthrough_content_type"], "application/json"
        )
        self.assertEqual(result["_dontlie_passthrough_body"], error_body.decode())
        self.assertEqual(storage.list_receipts(limit=1)[0].extra["status"], 401)


class ListSearchExportTest(unittest.TestCase):
    def setUp(self):
        _fresh_keypair()
        _fresh_db(f"vault-list-{id(self)}.db")
        storage.append(model="m1", prompt="alpha bravo", response="charlie", tags=["a"])
        storage.append(model="m2", prompt="delta", response="echo foxtrot", tags=["b"])
        storage.append(model="m3", prompt="alpha", response="golf", tags=["a", "b"])

    def test_list_orders_newest_first(self):
        rows = storage.list_receipts(limit=10)
        self.assertEqual([r.id for r in rows], [3, 2, 1])

    def test_search_finds_by_prompt_response_tags(self):
        hits_prompt = storage.search("alpha")
        self.assertEqual({r.id for r in hits_prompt}, {1, 3})
        # "b" appears in prompt of row 1 ("alpha bravo"), response of row 2
        # ("echo foxtrot" doesn't contain b; tag "b" of row 2 matches), and
        # tags of row 3. So all three rows match.
        hits_tag = storage.search("b")
        self.assertEqual({r.id for r in hits_tag}, {1, 2, 3})
        hits_response = storage.search("foxtrot")
        self.assertEqual([r.id for r in hits_response], [2])

    def test_export_writes_jsonl_with_all_rows(self):
        out = Path(_TMP) / f"export-{id(self)}.jsonl"
        n = storage.export(out)
        self.assertEqual(n, 3)
        lines = out.read_text().strip().splitlines()
        self.assertEqual(len(lines), 3)
        first = json.loads(lines[0])
        self.assertEqual(first["id"], 1)
        self.assertIn("signature", first)
        self.assertIn("payload_sha256", first)

    def test_count(self):
        self.assertEqual(storage.count(), 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
