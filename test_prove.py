"""Buyer workflow tests for ``dontlie prove`` evidence packets."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from dontlie import __version__, cli, prove, storage
from dontlie import sign as signing


class ProveCommandTest(unittest.TestCase):
    def setUp(self) -> None:
        self.old_paths = (
            signing.KEY_DIR,
            signing.PRIVATE_FILE,
            signing.PUBLIC_FILE,
            signing.KEY_ID_FILE,
            storage.DB_PATH,
        )
        self.temp_dir = tempfile.TemporaryDirectory(prefix="dontlie-prove-test-")
        self.root = Path(self.temp_dir.name)
        signing.KEY_DIR = self.root / "keys"
        signing.PRIVATE_FILE = signing.KEY_DIR / "dontlie.key"
        signing.PUBLIC_FILE = signing.KEY_DIR / "dontlie.pub"
        signing.KEY_ID_FILE = signing.KEY_DIR / "key_id"
        storage.DB_PATH = self.root / "vault.db"
        signing.generate()
        storage.init()

    def tearDown(self) -> None:
        (
            signing.KEY_DIR,
            signing.PRIVATE_FILE,
            signing.PUBLIC_FILE,
            signing.KEY_ID_FILE,
            storage.DB_PATH,
        ) = self.old_paths
        self.temp_dir.cleanup()

    def _append_receipts(self) -> None:
        storage.append(
            "buyer-model",
            "first prompt",
            "first response",
            extra={"endpoint": "/v1/chat/completions"},
        )
        storage.append(
            "buyer-model",
            "second prompt",
            "second response",
            extra={"endpoint": "/v1/chat/completions"},
        )

    def test_success_builds_complete_packet_with_limited_claims(self) -> None:
        self._append_receipts()
        output = self.root / "buyer-evidence"

        stdout = StringIO()
        with redirect_stdout(stdout):
            exit_code = cli.main(
                ["prove", str(output), "--title", "Acme evidence"]
            )

        self.assertEqual(exit_code, 0)
        self.assertIn(f"proved 2 receipts -> {output}", stdout.getvalue())
        self.assertEqual(
            {path.name for path in output.iterdir()},
            {
                prove.BUNDLE_NAME,
                prove.REPORT_NAME,
                prove.MANIFEST_NAME,
                prove.CHECKSUMS_NAME,
                prove.VERIFY_NAME,
            },
        )
        manifest = json.loads(
            (output / prove.MANIFEST_NAME).read_text(encoding="utf-8")
        )
        self.assertEqual(manifest["format"], prove.PACKET_FORMAT)
        self.assertEqual(manifest["version"], prove.PACKET_VERSION)
        self.assertEqual(manifest["dontlie_version"], __version__)
        self.assertEqual(manifest["receipt_count"], 2)
        self.assertEqual(manifest["integrity"]["result"], "verified")
        self.assertEqual(
            manifest["claims"],
            {
                "chain_integrity": "verified",
                "signer_identity": "requires external key pinning",
                "provider_identity": "recorded, not independently attested",
                "answer_truth": "not evaluated",
            },
        )
        report = (output / prove.REPORT_NAME).read_text(encoding="utf-8")
        self.assertIn("<title>Acme evidence</title>", report)

    def test_hashes_and_standard_sha256sums_verification(self) -> None:
        self._append_receipts()
        output = self.root / "hash-evidence"
        self.assertEqual(cli.main(["prove", str(output)]), 0)

        manifest = json.loads(
            (output / prove.MANIFEST_NAME).read_text(encoding="utf-8")
        )
        for artifact_name in (prove.BUNDLE_NAME, prove.REPORT_NAME):
            actual = hashlib.sha256(
                (output / artifact_name).read_bytes()
            ).hexdigest()
            self.assertEqual(
                manifest["artifacts"][artifact_name]["sha256"],
                actual,
            )

        checked = subprocess.run(
            ["shasum", "-a", "256", "-c", prove.CHECKSUMS_NAME],
            cwd=output,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertIn(f"{prove.BUNDLE_NAME}: OK", checked.stdout)
        self.assertIn(f"{prove.REPORT_NAME}: OK", checked.stdout)

    def test_exported_bundle_is_verified_before_publication(self) -> None:
        self._append_receipts()
        output = self.root / "verified-export"

        with patch(
            "dontlie.prove.storage.verify_export",
            return_value=storage.VerificationReport(
                ok_count=1,
                bad_count=1,
                issues=(
                    storage.VerificationIssue(
                        receipt_id=2,
                        reason="simulated exported-bundle failure",
                    ),
                ),
            ),
        ) as verify_export:
            stderr = StringIO()
            with redirect_stderr(stderr):
                exit_code = cli.main(["prove", str(output)])

        self.assertEqual(exit_code, 1)
        verify_export.assert_called_once()
        self.assertIn("exported bundle failed verification", stderr.getvalue())
        self.assertFalse(output.exists())
        self.assertEqual(
            list(self.root.glob(".verified-export.staging-*")),
            [],
        )

    def test_invalid_source_chain_is_refused(self) -> None:
        self._append_receipts()
        with sqlite3.connect(storage.DB_PATH) as conn:
            conn.execute(
                "UPDATE receipts SET response = ? WHERE id = 1",
                ("tampered after signing",),
            )
        output = self.root / "invalid-evidence"

        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = cli.main(["prove", str(output)])

        self.assertEqual(exit_code, 1)
        self.assertIn("source receipt chain is invalid", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_empty_vault_is_refused(self) -> None:
        output = self.root / "empty-evidence"

        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = cli.main(["prove", str(output)])

        self.assertEqual(exit_code, 1)
        self.assertIn("cannot prove an empty receipt vault", stderr.getvalue())
        self.assertFalse(output.exists())

    def test_existing_nonempty_output_directory_is_not_modified(self) -> None:
        self._append_receipts()
        output = self.root / "existing"
        output.mkdir()
        marker = output / "keep.txt"
        marker.write_text("preserve me", encoding="utf-8")

        stderr = StringIO()
        with redirect_stderr(stderr):
            exit_code = cli.main(["prove", str(output)])

        self.assertEqual(exit_code, 1)
        self.assertIn("output directory is not empty", stderr.getvalue())
        self.assertEqual(marker.read_text(encoding="utf-8"), "preserve me")
        self.assertEqual(list(output.iterdir()), [marker])

    def test_help_documents_command_and_title(self) -> None:
        parser = cli.build_parser()
        self.assertIn("prove", parser.format_help())

        stdout = StringIO()
        with self.assertRaisesRegex(SystemExit, "0"), redirect_stdout(stdout):
            cli.main(["prove", "--help"])
        help_text = stdout.getvalue()
        self.assertIn("OUTPUT_DIR", help_text)
        self.assertIn("--title", help_text)
        self.assertIn("portable evidence packet", help_text)

    def test_packet_report_has_no_demo_specific_paths(self) -> None:
        self._append_receipts()
        output = self.root / "generic-report"
        self.assertEqual(cli.main(["prove", str(output)]), 0)

        report = (output / prove.REPORT_NAME).read_text(encoding="utf-8")
        self.assertNotIn("/tmp/dontlie-demo-work", report)
        self.assertNotIn("tamper_walkthrough", report)
        self.assertIn(
            "dontlie verify --export receipts.bundle.json --verbose",
            report,
        )

    def test_verify_file_uses_versioned_github_wheel_without_pypi_claim(self) -> None:
        self._append_receipts()
        output = self.root / "verify-instructions"
        self.assertEqual(cli.main(["prove", str(output)]), 0)

        instructions = (output / prove.VERIFY_NAME).read_text(encoding="utf-8")
        expected_wheel = (
            "https://github.com/Matrix-ops77/dont-lie/releases/download/"
            f"v{__version__}/dontlie-{__version__}-py3-none-any.whl"
        )
        self.assertIn("shasum -a 256 -c SHA256SUMS", instructions)
        self.assertIn(
            "dontlie verify --export receipts.bundle.json --verbose",
            instructions,
        )
        self.assertIn(expected_wheel, instructions)
        self.assertNotIn("pypi", instructions.lower())


if __name__ == "__main__":
    unittest.main()
