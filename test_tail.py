"""Smoke tests for the tail (SIEM NDJSON streaming) module.

Run: python3 -m unittest test_tail
"""
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

from dontlie import storage, sign as signing


class TailTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="dontlie-tail-test-"))
        self._keys = self._tmp / "keys"
        self._keys.mkdir()
        self._db = self._tmp / "vault.db"
        self._saved = {
            k: os.environ.get(k)
            for k in ("DONTLIE_KEY_DIR", "DONTLIE_DB", "DONTLIE_NO_WAL")
        }
        os.environ["DONTLIE_KEY_DIR"] = str(self._keys)
        os.environ["DONTLIE_DB"] = str(self._db)
        os.environ["DONTLIE_NO_WAL"] = "1"
        import importlib
        importlib.reload(signing)
        signing.KEY_DIR = self._keys
        signing.PRIVATE_FILE = self._keys / "dontlie.key"
        signing.PUBLIC_FILE = self._keys / "dontlie.pub"
        signing.KEY_ID_FILE = self._keys / "key_id"
        signing.generate()
        importlib.reload(storage)
        storage.init()

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_json_mode_emits_one_receipt_per_line(self) -> None:
        storage.append(model="gpt-4o-mini", prompt="alpha", response="1")
        storage.append(model="gpt-4o-mini", prompt="beta", response="2")
        # Capture stdout
        from dontlie import tail as _tail
        buf = io.StringIO()
        saved_stdout = sys.stdout
        sys.stdout = buf
        try:
            rc = _tail.main(["--last", "2", "--json"])
        finally:
            sys.stdout = saved_stdout
        self.assertEqual(rc, 0)
        lines = [l for l in buf.getvalue().splitlines() if l]
        self.assertEqual(len(lines), 2)
        for line in lines:
            d = json.loads(line)
            self.assertIn("payload_sha256", d)
            self.assertIn("signature", d)
            self.assertEqual(d["_source"], "dontlie")
            self.assertIn("_vault", d)


if __name__ == "__main__":
    unittest.main()
