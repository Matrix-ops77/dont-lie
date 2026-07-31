"""Tests for the machine-readable evidence-support maps."""

from __future__ import annotations

import json
import unittest

from dontlie import compliance
from dontlie.cli import build_parser


class ComplianceMapTests(unittest.TestCase):
    def test_framework_ids_are_stable(self) -> None:
        self.assertEqual(
            sorted(compliance.FRAMEWORKS),
            ["eu-ai-act", "hipaa-security"],
        )

    def test_every_control_has_an_official_https_source(self) -> None:
        for framework in compliance.FRAMEWORKS.values():
            for control in framework.controls:
                self.assertTrue(control.source_url.startswith("https://"))
                self.assertIn(
                    control.coverage,
                    {
                        "supported",
                        "supporting_evidence",
                        "operator_required",
                        "out_of_scope",
                    },
                )

    def test_hipaa_does_not_claim_whole_program_coverage(self) -> None:
        hipaa = compliance.get_framework("hipaa-security")
        coverage = {control.coverage for control in hipaa.controls}
        self.assertIn("operator_required", coverage)
        self.assertIn("out_of_scope", coverage)
        self.assertNotIn("compliant", compliance.render_text(hipaa).lower())

    def test_eu_article_12_is_supporting_evidence_not_compliance(self) -> None:
        eu = compliance.get_framework("eu-ai-act")
        article_12 = next(
            control for control in eu.controls if control.control_id == "Article 12"
        )
        self.assertEqual(article_12.coverage, "supporting_evidence")
        self.assertIn("all required events", article_12.operator_action)

    def test_gap_filter_removes_supported_rows(self) -> None:
        framework = compliance.get_framework("hipaa-security")
        rendered = json.loads(compliance.render_json(framework, only_gaps=True))
        self.assertTrue(rendered["controls"])
        self.assertTrue(
            all(
                control["coverage"] in {"operator_required", "out_of_scope"}
                for control in rendered["controls"]
            )
        )

    def test_json_is_deterministic(self) -> None:
        framework = compliance.get_framework("eu-ai-act")
        self.assertEqual(
            compliance.render_json(framework),
            compliance.render_json(framework),
        )

    def test_cli_parser_accepts_compliance_command(self) -> None:
        args = build_parser().parse_args(
            ["compliance", "hipaa-security", "--json", "--only-gaps"]
        )
        self.assertEqual(args.framework, "hipaa-security")
        self.assertTrue(args.json)
        self.assertTrue(args.only_gaps)

    def test_unknown_framework_is_explicit(self) -> None:
        with self.assertRaisesRegex(ValueError, "unknown framework"):
            compliance.get_framework("not-real")


if __name__ == "__main__":
    unittest.main()
