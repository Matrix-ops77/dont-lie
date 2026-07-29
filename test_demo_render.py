"""Focused tests for the self-contained HTML proof report."""

from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

# This test file lives at <repo>/test_*.py, so the demo sources are
# inside the dontlie package at <repo>/dontlie/demo/ (shipped as a
# sub-package so `pip install dontlie` makes `dontlie demo` work).
PROJECT_ROOT = Path(__file__).resolve().parent
RENDER_SCRIPT = PROJECT_ROOT / "dontlie" / "demo" / "render_report.py"
SAMPLE_BUNDLE = PROJECT_ROOT / "demo" / "samples" / "receipts.bundle.json"

# render_report is now a proper sub-module — import it that way.
from dontlie.demo import render_report


class DemoRenderTest(unittest.TestCase):
    def test_valid_bundle_renders_verified_proof_sections(self) -> None:
        report = render_report.render(SAMPLE_BUNDLE)

        self.assertIn('<span class="badge good">VERIFIED</span>', report)
        self.assertIn("<strong>3</strong>valid receipts", report)
        self.assertIn("<h3>Integrity</h3>", report)
        self.assertIn("<h3>Signer</h3>", report)
        self.assertIn("<h3>Provider</h3>", report)
        self.assertIn("<h3>Truth</h3>", report)
        self.assertIn("<code>mock-1</code>", report)
        self.assertIn("<code>/v1/chat/completions</code>", report)

    def test_tampered_bundle_renders_failed_verdict_and_finding(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dontlie-render-test-") as temp:
            bundle = Path(temp) / "tampered.bundle.json"
            document = json.loads(SAMPLE_BUNDLE.read_text(encoding="utf-8"))
            document["receipts"][1]["response"] = "tampered after signing"
            bundle.write_text(json.dumps(document), encoding="utf-8")

            report = render_report.render(bundle)

        self.assertIn('<span class="badge bad">FAILED</span>', report)
        self.assertIn("<strong>1</strong>invalid receipts", report)
        self.assertIn("sha256 mismatch", report)

    def test_report_is_self_contained_and_escapes_bundle_values(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dontlie-render-test-") as temp:
            bundle = Path(temp) / "hostile.bundle.json"
            document = json.loads(SAMPLE_BUNDLE.read_text(encoding="utf-8"))
            document["receipts"][0]["extra"]["endpoint"] = (
                '<script src="https://attacker.invalid/x.js"></script>'
            )
            bundle.write_text(json.dumps(document), encoding="utf-8")

            report = render_report.render(bundle)

        self.assertNotIn("<script", report.lower())
        self.assertNotIn(" href=", report.lower())
        self.assertIn("&lt;script src=&quot;https://attacker.invalid", report)

    def test_main_writes_report_and_returns_success(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dontlie-render-test-") as temp:
            output = Path(temp) / "nested" / "proof.html"
            stdout = StringIO()
            with redirect_stdout(stdout):
                exit_code = render_report.main(
                    [str(SAMPLE_BUNDLE), str(output)]
                )

            self.assertEqual(exit_code, 0)
            self.assertTrue(output.exists())
            self.assertIn("<!doctype html>", output.read_text(encoding="utf-8"))
            self.assertIn(f"wrote {output}", stdout.getvalue())

    def test_main_reports_missing_bundle(self) -> None:
        with tempfile.TemporaryDirectory(prefix="dontlie-render-test-") as temp:
            missing = Path(temp) / "missing.json"
            stderr = StringIO()
            with redirect_stderr(stderr):
                exit_code = render_report.main(
                    [str(missing), str(Path(temp) / "proof.html")]
                )

        self.assertEqual(exit_code, 1)
        self.assertIn(f"missing bundle: {missing}", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
