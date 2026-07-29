"""Smoke tests for the 8 new capabilities: decision, annotate, policy, anchor, import, witness, siem, trust-per-receipt.

Run: python3 -m unittest test_capabilities
"""
import json
import os
import tempfile
import unittest
from pathlib import Path

from dontlie import sign as signing
from dontlie import storage


class CapabilitiesTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="dontlie-cap-test-"))
        self._keys = self._tmp / "keys"
        self._keys.mkdir()
        self._db = self._tmp / "vault.db"
        self._saved = {k: os.environ.get(k) for k in ("DONTLIE_KEY_DIR", "DONTLIE_DB", "DONTLIE_NO_WAL")}
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
        # Initialize the decision/annotation schemas
        from dontlie import annotate as _annotate
        from dontlie import decision as _decision
        _decision.init()
        _annotate.init()

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_decision_create_and_verify(self) -> None:
        from dontlie import decision
        r1 = storage.append(model="gpt-4o-mini", prompt="a", response="1")
        r2 = storage.append(model="gpt-4o-mini", prompt="b", response="2")
        d = decision.create(name="test", actor="me", receipt_ids=[r1.id, r2.id])
        self.assertGreater(d.id, 0)
        self.assertTrue(decision.verify(d))

    def test_annotate_create_and_verify(self) -> None:
        from dontlie import annotate
        r1 = storage.append(model="gpt-4o-mini", prompt="a", response="1")
        a = annotate.create(actor="gc", note="verified", receipt_ids=[r1.id])
        self.assertTrue(annotate.verify(a))

    def test_policy_evaluation(self) -> None:
        from dontlie import policy
        p = policy.Policy(deny_models=["*-preview"], redact_pii=True)
        d1 = policy.evaluate(p, model="gpt-4", prompt="hi")
        d2 = policy.evaluate(p, model="gpt-4-preview", prompt="hi")
        d3 = policy.evaluate(p, model="gpt-4", prompt="email jane@example.com")
        self.assertTrue(d1.allowed)
        self.assertFalse(d2.allowed)
        self.assertTrue(any("email" in r for r in d3.redactions))

    def test_siem_ocsf_and_ecs(self) -> None:
        from dontlie import siem
        r = storage.append(model="gpt-4o-mini", prompt="a", response="1")
        ocsf = siem.to_ocsf(r)
        ecs = siem.to_ecs(r)
        self.assertEqual(ocsf["class_name"], "API Activity")
        self.assertEqual(ocsf["type_uid"], 600301)
        self.assertEqual(ecs["event"]["action"], "ai-call-signed")

    def test_trust_per_receipt(self) -> None:
        from dontlie import trust
        r = storage.append(model="gpt-4o-mini", prompt="a", response="1")
        s = trust.score_receipt(r)
        self.assertGreater(s["value"], 80)
        self.assertIn("signature_valid", s["components"])

    def test_import_generic_jsonl(self) -> None:
        from dontlie import importers
        # write a temp JSONL
        with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as f:
            for i in range(3):
                f.write(json.dumps({"model": "gpt-4o", "prompt": f"p{i}", "response": f"r{i}"}) + "\n")
            tmpname = f.name
        result = importers.import_file(Path(tmpname), format="generic-jsonl")
        self.assertEqual(result.imported, 3)
        self.assertEqual(result.first_id, 1)  # first id on a fresh vault

    def test_witness_service_handler(self) -> None:
        # We don't run the server in tests, but we can construct a handler
        # and call it with a stubbed request. Skip the network test here.
        from dontlie.witness_service import _is_valid_sha256
        self.assertTrue(_is_valid_sha256("a" * 64))
        self.assertFalse(_is_valid_sha256("not-a-hash"))
        self.assertFalse(_is_valid_sha256("a" * 63))


if __name__ == "__main__":
    unittest.main()
