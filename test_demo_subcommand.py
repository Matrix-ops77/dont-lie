import os
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from test_helpers import with_dontlie_env

_TMP = tempfile.mkdtemp(prefix="dontlie-demo-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

# This test file lives at <repo>/test_*.py; the demo sources are
# inside the dontlie package at <repo>/dontlie/demo/ (shipped as a
# sub-package so `pip install dontlie` makes `dontlie demo` work).
REPO_ROOT = Path(__file__).resolve().parent
DEMO_PKG = REPO_ROOT / "dontlie" / "demo"
RUN_DEMO = DEMO_PKG / "run_offline_demo.sh"
TAMPER_WALK = DEMO_PKG / "tamper_walkthrough.py"
CLEANUP = DEMO_PKG / "cleanup.py"

DEMO_LOCK = Path(tempfile.gettempdir()) / "dontlie-demo-test.lock"

from dontlie import storage


def _demo_lock() -> None:
    while DEMO_LOCK.exists():
        time.sleep(0.2)
    DEMO_LOCK.touch()


def _demo_unlock() -> None:
    DEMO_LOCK.unlink(missing_ok=True)


def _isolated_work(test_id: int) -> Path:
    work = Path(_TMP) / f"work-{test_id}"
    if work.exists():
        subprocess.run([sys.executable, str(CLEANUP), str(work)], check=False)
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)
    return work


class DemoSubcommandRegistrationTest(unittest.TestCase):
    def test_cli_demo_registered_as_subcommand(self) -> None:
        from dontlie import cli
        result = subprocess.run(
            [sys.executable, "-m", "dontlie", "--help"],
            cwd=str(REPO_ROOT),
            env=with_dontlie_env(),
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("demo", result.stdout)
        self.assertIn("run the offline proof experience", result.stdout)
        self.assertTrue(callable(cli.cmd_demo))

    def test_build_parser_includes_demo_choice(self) -> None:
        from dontlie import cli
        parser = cli.build_parser()
        sub_action = next(a for a in parser._actions if a.dest == "cmd")
        self.assertIn("demo", sub_action.choices)


class DemoSubcommandExecutionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.work = _isolated_work(id(self))
        self.env = with_dontlie_env()
        self.env["DONTLIE_DEMO_WORK"] = str(self.work)
        _demo_lock()

    def tearDown(self) -> None:
        subprocess.run([sys.executable, str(CLEANUP), str(self.work)], check=False)
        shutil.rmtree(self.work, ignore_errors=True)
        _demo_unlock()

    def test_run_offline_demo_script_exits_zero(self) -> None:
        result = subprocess.run(
            ["bash", str(RUN_DEMO)],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        vault = self.work / "vault.db"
        jsonl = self.work / "receipts.jsonl"
        bundle = self.work / "receipts.bundle.json"
        self.assertTrue(vault.exists())
        self.assertTrue(jsonl.exists())
        self.assertTrue(bundle.exists())
        with sqlite3.connect(vault) as conn:
            count = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        self.assertGreaterEqual(count, 3)
        self.assertIn("Demo complete", result.stdout)
        self.assertIn("TAMPER-PROOF CHECK", result.stdout)

    def test_cli_demo_dispatch_invokes_subprocess(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "dontlie", "demo"],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(
            result.returncode,
            0,
            msg=f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}",
        )
        self.assertIn("Demo complete", result.stdout)


class TamperWalkthroughPipingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.work = _isolated_work(id(self) + 50000)
        self.env = with_dontlie_env()
        self.env["DONTLIE_DEMO_WORK"] = str(self.work)
        _demo_lock()

    def tearDown(self) -> None:
        subprocess.run([sys.executable, str(CLEANUP), str(self.work)], check=False)
        shutil.rmtree(self.work, ignore_errors=True)
        _demo_unlock()

    def test_tamper_walkthrough_runs_and_detects(self) -> None:
        seed = subprocess.run(
            ["bash", str(RUN_DEMO)],
            cwd=str(REPO_ROOT),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(seed.returncode, 0, msg=f"seed stderr:\n{seed.stderr}")
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
        self.assertIn("STAGE 3: verify tampered vault", combined)
        self.assertIn("STAGE 5: restore the original signed records", combined)
        self.assertIn("STAGE 6: verify restored vault", combined)
        with sqlite3.connect(self.work / "vault.db") as conn:
            restored_count = conn.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
        self.assertEqual(restored_count, 3)
        final_report = storage.verify_chain_report()
        self.assertTrue(final_report.valid)


if __name__ == "__main__":
    unittest.main()
