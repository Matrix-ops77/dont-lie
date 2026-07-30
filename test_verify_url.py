"""test_verify_url.py — verify the self-contained verify-URL flow.

The pledge: a dontlie verify-url <id> produces a URL whose fragment
contains enough information for a browser, with no Dont-Lie account
and no Dont-Lie server, to verify the receipt's Ed25519 signature
entirely client-side. Anyone with the URL can verify offline.

This test:
  1. Generates a real receipt in an isolated vault
  2. Calls verify-url to produce a URL
  3. Decodes the URL fragment back to a payload
  4. Verifies the payload locally (the same code path the JS verifier runs)
  5. Verifies signature bytes match the canonical form
  6. Verifies tampering with any field breaks the signature

Run: python3 -m unittest test_verify_url -v
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent


def _isolated_env() -> dict:
    """Build a clean env pointing at a temp DB and key dir."""
    tmp = Path(tempfile.mkdtemp(prefix="dontlie-verify-url-test-"))
    keys = tmp / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    env = os.environ.copy()
    env["DONTLIE_DB"] = str(tmp / "vault.db")
    env["DONTLIE_KEY_DIR"] = str(keys)
    env["DONTLIE_NO_WAL"] = "1"
    # Only prepend REPO_ROOT to PYTHONPATH when dontlie is NOT already
    # importable from a venv (wheel or editable install). When the
    # package IS installed, setting PYTHONPATH here makes the subprocess
    # replace its site-packages with REPO_ROOT, which breaks
    # `import httpx` and similar — see test_helpers.py for the
    # full analysis. The downstream subprocess in _make_receipt uses
    # `from dontlie import storage` which resolves via the venv, so
    # it does not need PYTHONPATH either.
    try:
        import dontlie  # noqa: F401
        _NEEDS_PYTHONPATH = False
    except ImportError:
        _NEEDS_PYTHONPATH = True
    if _NEEDS_PYTHONPATH:
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _make_receipt(env: dict) -> None:
    """Generate a key and sign one v3 receipt in the isolated vault."""
    subprocess.run(
        [sys.executable, "-m", "dontlie", "gen-key"],
        env=env, check=True, capture_output=True,
    )
    # v3 fields come from env vars (DONTLIE_OPERATOR_ID etc.)
    v3_env = dict(env)
    v3_env["DONTLIE_OPERATOR_ID"] = "op-test-1234"
    v3_env["DONTLIE_DEPLOYER_ID"] = "dep-test-5678"
    v3_env["DONTLIE_SYSTEM_ID"] = "sys-test-9abc"
    subprocess.run(
        [
            sys.executable, "-c",
            ("import sys; sys.path.insert(0, '.'); "
            "from dontlie import storage; "
            "storage.append(model='test-model-v3', prompt='verify-url test prompt', "
            "response='verify-url test response')")
        ],
        env=v3_env, check=True, capture_output=True, cwd=str(REPO_ROOT),
    )


class TestVerifyURL(unittest.TestCase):
    """End-to-end test of the verify-url flow."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.env = _isolated_env()
        _make_receipt(cls.env)
        # Set the env in-process so storage.DB_PATH / signing.KEY_DIR
        # point at the test vault. The cli() test cases use subprocess
        # to set the env fresh; the verify_payload_locally() tests
        # need the in-process env to read the test receipt.
        for k, v in cls.env.items():
            os.environ[k] = v
        # Force the storage module to re-read its env-derived paths
        from dontlie import sign as signing
        from dontlie import storage
        storage.DB_PATH = Path(cls.env["DONTLIE_DB"])
        signing.KEY_DIR = Path(cls.env["DONTLIE_KEY_DIR"])
        signing.PRIVATE_FILE = signing.KEY_DIR / "dontlie.key"
        signing.PUBLIC_FILE = signing.KEY_DIR / "dontlie.pub"
        signing.KEY_ID_FILE = signing.KEY_DIR / "key_id"

    def test_verify_url_generates_valid_url(self) -> None:
        """dontlie verify-url 1 produces a URL whose fragment is a valid payload."""
        from dontlie import storage, verify_url

        receipt = storage.get_receipt(1)
        self.assertIsNotNone(receipt, "fixture: receipt #1 should exist")

        url = verify_url.encode_url(receipt, base_url="https://example.com/")
        # Must be a URL with #v= fragment
        self.assertIn("#v=", url, f"URL must have #v= fragment: {url[:80]}")
        # Fragment must be base64url (no +, /, = in the encoded part)
        fragment = url.split("#v=", 1)[1]
        self.assertNotIn("+", fragment, "fragment must be base64url (no +)")
        self.assertNotIn("/", fragment, "fragment must be base64url (no /)")
        self.assertNotIn("=", fragment, "fragment must be base64url-padless (no =)")

        # Decode it back
        payload = verify_url.decode_fragment(fragment)
        self.assertEqual(payload["v"], 1)
        self.assertIn("receipt", payload)
        self.assertIn("public_key_pem", payload)
        self.assertIn("-----BEGIN PUBLIC KEY-----", payload["public_key_pem"])

    def test_verify_url_local_verify_succeeds(self) -> None:
        """decode + verify_payload_locally returns ok=True for a real receipt."""
        from dontlie import storage, verify_url

        receipt = storage.get_receipt(1)
        url = verify_url.encode_url(receipt, base_url="https://example.com/")
        fragment = url.split("#v=", 1)[1]
        payload = verify_url.decode_fragment(fragment)
        ok, reason = verify_url.verify_payload_locally(payload)
        self.assertTrue(ok, f"local verify should succeed: {reason}")

    def test_verify_url_local_verify_cli(self) -> None:
        """The `dontlie verify-url <id> --verify` subcommand also succeeds."""
        result = subprocess.run(
            [sys.executable, "-m", "dontlie", "verify-url", "1", "--base-url", "https://example.com/", "--verify"],
            env=self.env, capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(
            result.returncode, 0,
            f"verify-url --verify should succeed. "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn("local verify OK", result.stderr)
        self.assertIn("https://example.com/#v=", result.stdout)

    def test_tampering_with_prompt_breaks_signature(self) -> None:
        """Modifying the prompt field in the payload should break verification."""
        from dontlie import storage, verify_url

        receipt = storage.get_receipt(1)
        url = verify_url.encode_url(receipt, base_url="https://example.com/")
        fragment = url.split("#v=", 1)[1]
        payload = verify_url.decode_fragment(fragment)

        # Tamper with the prompt
        payload["receipt"]["prompt"] = "TAMPERED prompt"

        ok, reason = verify_url.verify_payload_locally(payload)
        self.assertFalse(ok, "tampered prompt must fail verification")
        # The failure should mention either the canonical mismatch or the signature
        self.assertTrue(
            "body_canon" in reason or "signature" in reason,
            f"failure should mention canonical or signature mismatch, got: {reason!r}",
        )

    def test_tampering_with_signature_breaks_verification(self) -> None:
        """Replacing the signature with random bytes must fail."""
        import secrets

        from dontlie import storage, verify_url

        receipt = storage.get_receipt(1)
        url = verify_url.encode_url(receipt, base_url="https://example.com/")
        fragment = url.split("#v=", 1)[1]
        payload = verify_url.decode_fragment(fragment)

        # Replace the signature with random bytes (also base64-encoded)
        random_bytes = secrets.token_bytes(64)
        payload["receipt"]["signature"] = base64.b64encode(random_bytes).decode("ascii")

        ok, _reason = verify_url.verify_payload_locally(payload)
        self.assertFalse(ok, "tampered signature must fail verification")

    def test_tampering_with_response_breaks_verification(self) -> None:
        """Modifying the response field in the payload should break verification."""
        from dontlie import storage, verify_url

        receipt = storage.get_receipt(1)
        url = verify_url.encode_url(receipt, base_url="https://example.com/")
        fragment = url.split("#v=", 1)[1]
        payload = verify_url.decode_fragment(fragment)

        payload["receipt"]["response"] = "TAMPERED response"
        ok, _reason = verify_url.verify_payload_locally(payload)
        self.assertFalse(ok, "tampered response must fail verification")

    def test_format_version_mismatch_is_rejected(self) -> None:
        """A payload with v=99 must be rejected by decode_fragment."""
        from dontlie import verify_url

        bad_payload = {
            "v": 99,
            "url": "https://example.com/verify/",
            "issued_at": "2026-07-29T00:00:00Z",
            "receipt": {"id": 1, "timestamp": "x", "model": "x", "prompt": "x", "response": "x",
                        "parent_id": None, "key_id": "x", "payload_sha256": "x", "tags": [],
                        "extra": {}, "body_canon": "x", "signature": "x"},
            "public_key_pem": "-----BEGIN PUBLIC KEY-----\nxxx\n-----END PUBLIC KEY-----\n",
        }
        encoded = base64.urlsafe_b64encode(
            json.dumps(bad_payload, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=").decode("ascii")
        with self.assertRaises(ValueError) as ctx:
            verify_url.decode_fragment(encoded)
        self.assertIn("format version", str(ctx.exception).lower())

    def test_corrupt_fragment_is_rejected(self) -> None:
        """Garbage in the fragment should raise ValueError, not crash."""
        from dontlie import verify_url

        with self.assertRaises(ValueError):
            verify_url.decode_fragment("not-base64-at-all!!!")

    def test_url_writes_to_out_file(self) -> None:
        """`dontlie verify-url 1 --out <path>` writes the URL to the file."""
        with tempfile.NamedTemporaryFile(suffix=".url", delete=False) as tmp:
            out_path = Path(tmp.name)
        try:
            result = subprocess.run(
                [sys.executable, "-m", "dontlie", "verify-url", "1", "--base-url", "https://example.com/", "--out", str(out_path)],
                env=self.env, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, f"stderr: {result.stderr}")
            content = out_path.read_text().strip()
            self.assertTrue(content.startswith("https://"), f"file should contain URL: {content!r}")
            self.assertIn("#v=", content)
        finally:
            if out_path.exists():
                out_path.unlink()

    def test_thirty_two_subcommands_still_registered(self) -> None:
        """Belt-and-suspenders: the verify-url addition must not have
        broken the parser (v0.3.3 fixed an early-return bug)."""
        result = subprocess.run(
            [sys.executable, "-m", "dontlie", "--help"],
            env=self.env, capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0)
        # The subcommands appear in the comma-separated list in the
        # usage line: "{cmd1,cmd2,...,cmdN}". Extract and count.
        import re
        m = re.search(r"\{([^}]+)\}", result.stdout)
        self.assertIsNotNone(m, f"could not find subcommand list in: {result.stdout[:500]!r}")
        cmds = [c.strip() for c in m.group(1).split(",") if c.strip()]
        self.assertGreaterEqual(
            len(cmds), 32,
            f"expected 32+ subcommands after adding verify-url, got {len(cmds)}: {cmds}",
        )
        # And specifically that verify-url is there
        self.assertIn("verify-url", cmds, "verify-url subcommand should be registered")


if __name__ == "__main__":
    unittest.main()
