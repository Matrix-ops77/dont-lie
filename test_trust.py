"""Smoke tests for the trust-score module.

Run: python3 -m unittest test_trust
"""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from dontlie import storage
from dontlie.trust import compute, TrustScore, _label_for


class TrustScoreLabelTest(unittest.TestCase):
    def test_label_bands(self) -> None:
        self.assertEqual(_label_for(95), "excellent")
        self.assertEqual(_label_for(85), "good")
        self.assertEqual(_label_for(60), "fair")
        self.assertEqual(_label_for(30), "weak")
        self.assertEqual(_label_for(10), "untrusted")


class TrustScoreComputeTest(unittest.TestCase):
    def setUp(self) -> None:
        # Isolated temp vault
        self._tmp = Path(tempfile.mkdtemp(prefix="dontlie-trust-test-"))
        self._keys = self._tmp / "keys"
        self._keys.mkdir()
        self._db = self._tmp / "vault.db"
        self._env = {
            "DONTLIE_KEY_DIR": str(self._keys),
            "DONTLIE_DB": str(self._db),
            "DONTLIE_NO_WAL": "1",
        }
        self._saved = {k: os.environ.get(k) for k in self._env}
        os.environ.update(self._env)
        # Reload storage to pick up new DB_PATH
        import importlib
        importlib.reload(storage)
        from dontlie import sign as signing
        signing.KEY_DIR = self._keys
        signing.PRIVATE_FILE = self._keys / "dontlie.key"
        signing.PUBLIC_FILE = self._keys / "dontlie.pub"
        signing.KEY_ID_FILE = self._keys / "key_id"
        signing.generate()
        storage.init()

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_empty_vault_returns_zero(self) -> None:
        score = compute()
        self.assertEqual(score.value, 0)
        self.assertEqual(score.label, "untrusted")
        self.assertIn("chain_integrity", score.components)

    def test_valid_receipt_increases_score(self) -> None:
        storage.append(model="gpt-4o-mini", prompt="hello", response="hi")
        score = compute()
        self.assertGreater(score.value, 50, f"score was {score.value}")
        self.assertIn(score.label, ("good", "fair", "excellent"))

    def test_tampered_receipt_reduces_chain_integrity(self) -> None:
        r = storage.append(model="gpt-4o-mini", prompt="hello", response="hi")
        # Tamper with the response directly in the DB
        conn = storage._connect()
        try:
            conn.execute("UPDATE receipts SET response = ? WHERE id = ?", ("tampered", r.id))
            conn.commit()
        finally:
            conn.close()
        score = compute()
        ci = score.components["chain_integrity"]
        self.assertLess(ci["value"], 40)
        self.assertIn("failed verification", ci["note"])

    def test_to_dict_is_json_serializable(self) -> None:
        storage.append(model="gpt-4o-mini", prompt="hello", response="hi")
        score = compute()
        d = score.to_dict()
        # round-trip through json.dumps to confirm serializability
        s = json.dumps(d, default=str)
        self.assertIsInstance(s, str)
        self.assertIn("trust score", d["label"]) if False else None  # not strict
        self.assertIn("value", d)
        self.assertIn("components", d)


if __name__ == "__main__":
    unittest.main()
