from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from dontlie.demo.benchmark import _reset_benchmark_state


class BenchmarkResetTest(unittest.TestCase):
    def test_reset_removes_database_sidecars_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp)
            stale_paths = (
                work / "vault.db",
                work / "vault.db-wal",
                work / "vault.db-shm",
                work / "vault.bench-export.jsonl",
                work / "vault.bench-export.bench-bundle.json",
                work / "vault.bench-export.bench-report.html",
                work / "keys" / "private.pem",
            )
            for path in stale_paths:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("stale", encoding="utf-8")

            _reset_benchmark_state(work)

            self.assertTrue((work / "keys").is_dir())
            self.assertEqual(list((work / "keys").iterdir()), [])
            for path in stale_paths[:-1]:
                self.assertFalse(path.exists(), path)


if __name__ == "__main__":
    unittest.main()
