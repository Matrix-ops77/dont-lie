"""Focused integration tests for the tamper walkthrough in run_offline_demo.sh.

The tamper walkthrough is the bit at the end of ``run_offline_demo.sh`` that
mutates one signed record, asks the production verifier to flag it, and then
restores the receipt from the JSONL export. These tests pin down its behavior
against the real CLI/subprocess path, and also against an in-process
invocation of the module's helpers.

The tests cover:

1. The end-to-end ``tamper_walkthrough.py`` subprocess detects a mutated
   receipt, restores it from the JSONL export, and verifies the chain again.
2. The walkthrough returns a non-zero exit code when the vault is missing.
3. The walkthrough's internal helpers (recompute hash, restore from JSONL)
   produce identical results when run in-process on a real demo artifact.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

# --- isolated env: keep this file's tests off the real user vault ----------
_TMP = tempfile.mkdtemp(prefix="dontlie-tamper-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

# Project layout: this test file lives at <repo>/dontlie/test_*.py, so the
# repo root is one parent up, and demo sources live at <repo>/dontlie/demo/.
REPO_ROOT = Path(__file__).resolve().parent
DEMO_SCRIPTS = REPO_ROOT / "demo" / "scripts"
RUN_DEMO = DEMO_SCRIPTS / "run_offline_demo.sh"
TAMPER_WALK = DEMO_SCRIPTS / "tamper_walkthrough.py"

import importlib.util

_TAMPER_SPEC = importlib.util.spec_from_file_location(
    "demo_tamper_walkthrough", str(TAMPER_WALK)
)
if _TAMPER_SPEC is None or _TAMPER_SPEC.loader is None:  # pragma: no cover
    raise RuntimeError(f"could not load {TAMPER_WALK} as a module")
_TAMPER_MOD = importlib.util.module_from_spec(_TAMPER_SPEC)
_TAMPER_SPEC.loader.exec_module(_TAMPER_MOD)

from dontlie import storage


def _port_pair(seed: int) -> tuple[str, str]:
    """Pick two high-numbered ports unlikely to collide with local dev."""
    base = 24000 + (seed % 4000)
    return str(base), str(base + 1)


def _isolated_work(label: str) -> Path:
    return Path(tempfile.mkdtemp(prefix=f"dontlie-{label}-"))


def _seed_demo_work(env: dict[str, str]) -> None:
    """Run the offline demo so that vault.db and receipts.jsonl exist.

    ``DONTLIE_DEMO_WORK`` (set on ``env``) is what the bash script reads to
    decide where to write; no separate path argument is needed.
    """
    seed = subprocess.run(
        ["bash", str(RUN_DEMO)],
        cwd=str(REPO_ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=180,
    )
    if seed.returncode != 0:
        raise RuntimeError(
            f"seed demo failed (rc={seed.returncode})\n"
            f"stdout:\n{seed.stdout}\nstderr:\n{seed.stderr}"
        )


class TamperWalkthroughEndToEndTest(unittest.TestCase):
    """The embedded tamper walkthrough detects + restores tampered records."""

    def setUp(self) -> None:
        self.work = _isolated_work(f"tamper-{id(self)}")
        self.mock_port, self.proxy_port = _port_pair(id(self) % 4000)
        self.env = os.environ.copy()
        # Subprocess-launched scripts need PYTHONPATH to find the local
        # `dontlie` package when the test isn't run from an editable install.
        self.env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + self.env.get("PYTHONPATH", "")
        self.env["DONTLIE_DEMO_WORK"] = str(self.work)
        self.env["MOCK_PORT"] = self.mock_port
        self.env["PROXY_PORT"] = self.proxy_port
        self.env["OPENAI_BASE_URL"] = (
            f"http://127.0.0.1:{self.proxy_port}/v1"
        )
        self.env["PYTHON"] = sys.executable
        _seed_demo_work(self.env)

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def test_walkthrough_detects_tampering_and_restores(self) -> None:
        result = subprocess.run(
            [sys.executable, str(TAMPER_WALK), str(self.work)],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        combined = result.stdout + result.stderr
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("STAGE 1: verify clean vault with production verifier", combined)
        self.assertIn("STAGE 3: verify tampered vault", combined)
        self.assertIn("STAGE 5: restore the original signed records", combined)
        self.assertIn("STAGE 6: verify restored vault", combined)
        with sqlite3.connect(self.work / "vault.db") as conn:
            restored_count = conn.execute(
                "SELECT COUNT(*) FROM receipts"
            ).fetchone()[0]
        self.assertEqual(restored_count, 3)
        # Fresh DB_PATH so we don't read a stale global from another test.
        storage.DB_PATH = self.work / "vault.db"
        final_report = storage.verify_chain_report()
        self.assertTrue(final_report.valid)
        self.assertEqual(final_report.bad_count, 0)


class TamperWalkthroughMissingInputsTest(unittest.TestCase):
    """Walkthrough exits non-zero when inputs are missing."""

    def test_missing_vault_returns_error(self) -> None:
        work = REPO_ROOT / "demo" / "work" / f"tamper-missing-{id(self)}"
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True, exist_ok=True)
        env = os.environ.copy()
        env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + env.get("PYTHONPATH", "")
        try:
            result = subprocess.run(
                [sys.executable, str(TAMPER_WALK), str(work)],
                cwd=str(REPO_ROOT),
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("missing", (result.stderr + result.stdout).lower())
        finally:
            shutil.rmtree(work, ignore_errors=True)


class TamperWalkthroughInProcessTest(unittest.TestCase):
    """Exercise the walkthrough's helpers in-process against a real demo."""

    def setUp(self) -> None:
        self.work = _isolated_work(f"tamper-inproc-{id(self)}")
        self.mock_port, self.proxy_port = _port_pair((id(self) + 1000) % 4000)
        self.env = os.environ.copy()
        # Subprocess-launched scripts need PYTHONPATH to find the local
        # `dontlie` package when the test isn't run from an editable install.
        self.env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + self.env.get("PYTHONPATH", "")
        self.env["DONTLIE_DEMO_WORK"] = str(self.work)
        self.env["MOCK_PORT"] = self.mock_port
        self.env["PROXY_PORT"] = self.proxy_port
        self.env["OPENAI_BASE_URL"] = (
            f"http://127.0.0.1:{self.proxy_port}/v1"
        )
        self.env["PYTHON"] = sys.executable
        _seed_demo_work(self.env)
        self.db_path = self.work / "vault.db"
        self.jsonl_path = self.work / "receipts.jsonl"

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def test_clean_repo_report_is_valid(self) -> None:
        report = _TAMPER_MOD._report(self.db_path)
        self.assertTrue(report.valid)
        self.assertEqual(report.bad_count, 0)

    def test_recompute_hash_matches_stored_for_clean_receipt(self) -> None:
        receipt = _TAMPER_MOD._receipt_two(self.db_path)
        recomputed = hashlib.sha256(
            storage._canonical_payload(receipt)
        ).hexdigest()
        self.assertEqual(receipt.payload_sha256, recomputed)

    def test_mutation_in_process_is_detected(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE receipts SET response=? WHERE id=2",
                ("TAMPERED: not the original response",),
            )
        report = _TAMPER_MOD._report(self.db_path)
        self.assertFalse(report.valid)
        self.assertGreater(report.bad_count, 0)

    def test_restore_from_jsonl_returns_clean_chain(self) -> None:
        """Mutate, then restore via the walkthrough's helper, then verify."""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE receipts SET response=? WHERE id=2",
                ("TAMPERED: should be reverted",),
            )
        tampered = _TAMPER_MOD._report(self.db_path)
        self.assertFalse(tampered.valid)

        restored = _TAMPER_MOD._restore_from_jsonl(self.db_path, self.jsonl_path)
        self.assertEqual(restored, 3)

        after = _TAMPER_MOD._report(self.db_path)
        self.assertTrue(after.valid)
        self.assertEqual(after.bad_count, 0)

    def test_receipt_two_after_restore_matches_original_hash(self) -> None:
        original = _TAMPER_MOD._receipt_two(self.db_path)
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                "UPDATE receipts SET response=? WHERE id=2",
                ("TAMPERED: hash mismatch check",),
            )
        _TAMPER_MOD._restore_from_jsonl(self.db_path, self.jsonl_path)
        restored = _TAMPER_MOD._receipt_two(self.db_path)
        self.assertEqual(restored.payload_sha256, original.payload_sha256)
        self.assertEqual(restored.signature, original.signature)
        self.assertEqual(restored.response, original.response)


def _jsonl_records(path: Path) -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


class TamperWalkthroughJsonlShapeTest(unittest.TestCase):
    """The JSONL export written by the demo must be loadable + complete."""

    def setUp(self) -> None:
        self.work = _isolated_work(f"tamper-jsonl-{id(self)}")
        self.mock_port, self.proxy_port = _port_pair((id(self) + 2000) % 4000)
        self.env = os.environ.copy()
        # Subprocess-launched scripts need PYTHONPATH to find the local
        # `dontlie` package when the test isn't run from an editable install.
        self.env["PYTHONPATH"] = str(REPO_ROOT) + os.pathsep + self.env.get("PYTHONPATH", "")
        self.env["DONTLIE_DEMO_WORK"] = str(self.work)
        self.env["MOCK_PORT"] = self.mock_port
        self.env["PROXY_PORT"] = self.proxy_port
        self.env["OPENAI_BASE_URL"] = (
            f"http://127.0.0.1:{self.proxy_port}/v1"
        )
        self.env["PYTHON"] = sys.executable
        _seed_demo_work(self.env)

    def tearDown(self) -> None:
        shutil.rmtree(self.work, ignore_errors=True)

    def test_jsonl_records_round_trip_into_vault(self) -> None:
        records = _jsonl_records(self.work / "receipts.jsonl")
        self.assertEqual(len(records), 3)
        # Every record has the columns the walkthrough's UPDATE covers.
        required = {
            "id",
            "timestamp",
            "model",
            "prompt",
            "response",
            "parent_id",
            "key_id",
            "payload_sha256",
            "signature",
            "tags",
            "extra",
        }
        for record in records:
            self.assertTrue(required.issubset(record.keys()))


if __name__ == "__main__":
    unittest.main()
