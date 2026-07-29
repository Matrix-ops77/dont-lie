"""Smoke tests for batch, namespace, registry, ots.

Run: python3 -m unittest test_v2_capabilities
"""
import os
import tempfile
import unittest
from pathlib import Path

from dontlie import sign as signing
from dontlie import storage


class V2CapabilitiesTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = Path(tempfile.mkdtemp(prefix="dontlie-v2-test-"))
        self._keys = self._tmp / "keys"
        self._keys.mkdir()
        self._db = self._tmp / "vault.db"
        self._saved = {k: os.environ.get(k) for k in
                       ("DONTLIE_KEY_DIR", "DONTLIE_DB", "DONTLIE_NO_WAL",
                        "DONTLIE_REGISTRY", "DONTLIE_NAMESPACE")}
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
        from dontlie import batch, namespace, registry
        batch.init()
        namespace.init()
        registry.load()  # don't install defaults — empty registry is fine for tests

    def tearDown(self) -> None:
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v
        import shutil
        shutil.rmtree(self._tmp, ignore_errors=True)

    def test_batch_create_and_verify(self) -> None:
        from dontlie import batch
        r1 = storage.append(model="gpt-4o-mini", prompt="a", response="1")
        r2 = storage.append(model="gpt-4o-mini", prompt="b", response="2")
        r3 = storage.append(model="gpt-4o-mini", prompt="c", response="3")
        b = batch.create([r1.id, r2.id, r3.id])
        self.assertEqual(b.leaf_count, 3)
        self.assertTrue(batch.verify(b))

    def test_batch_merkle_path(self) -> None:
        from dontlie import batch
        # 4 leaves
        h = [bytes(32) if i == 0 else bytes([i]) + b"\x00" * 31 for i in range(1, 5)]
        root = batch.merkle_root(h)
        # path from leaf 2
        path = batch.merkle_path(h, 1)
        self.assertTrue(batch.verify_merkle_path(h[1], 1, path, root))

    def test_namespace_isolation(self) -> None:
        from dontlie import namespace
        namespace.create("acme-corp", description="Acme's vault")
        # Write 2 receipts in default, 1 in acme
        os.environ.pop("DONTLIE_NAMESPACE", None)
        storage.append(model="gpt-4o-mini", prompt="default-1", response="x")
        storage.append(model="gpt-4o-mini", prompt="default-2", response="x")
        os.environ["DONTLIE_NAMESPACE"] = "acme-corp"
        storage.append(model="gpt-4o-mini", prompt="acme-1", response="x")
        # Count by namespace
        self.assertEqual(storage.count("default"), 2)
        self.assertEqual(storage.count("acme-corp"), 1)
        # Switch back and verify
        os.environ["DONTLIE_NAMESPACE"] = "default"
        self.assertEqual(len(storage.list_receipts(limit=10)), 2)

    def test_registry_match(self) -> None:
        from dontlie import registry
        reg = registry.default_registry()
        # Create a fake receipt
        r = storage.append(model="gpt-4o-mini", prompt="hi", response="hi")
        m = registry.match(r, reg)
        self.assertIsNotNone(m)
        self.assertEqual(m[0], "openai")
        # Local receipts should match local
        r2 = storage.append(model="llama3.1-70b", prompt="hi", response="hi")
        m2 = registry.match(r2, reg)
        # Could match meta (llama*) or local (* wildcard). Either way is a match.
        self.assertIsNotNone(m2)

    def test_ots_create_pending(self) -> None:
        from dontlie import ots
        r = storage.append(model="gpt-4o-mini", prompt="hi", response="hi")
        a = ots.create_pending(r.id, output_dir=self._tmp / "ots")
        self.assertTrue(a.file_path.exists())
        # OTS file should start with the OTS_MAGIC
        self.assertEqual(a.file_path.read_bytes()[:3], ots.OTS_MAGIC)

    def test_web_works_with_namespace(self) -> None:
        # Just confirm the web module's import doesn't break with the new schema
        from dontlie import web
        self.assertTrue(hasattr(web, "main"))


if __name__ == "__main__":
    unittest.main()
