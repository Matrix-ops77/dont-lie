"""Tests for dontlie.privacy — evidence modes and redaction detectors.

Run: python -m unittest test_privacy.py
"""

import json
import os
import tempfile
import unittest
from pathlib import Path

# Mirror the dontlie test isolation pattern so the privacy module
# never accidentally touches the real keychain or vault directory.
_TMP = tempfile.mkdtemp(prefix="dontlie-privacy-test-")
os.environ["DONTLIE_KEY_DIR"] = str(Path(_TMP) / "keys")
os.environ["DONTLIE_DB"] = str(Path(_TMP) / "vault.db")
os.environ["DONTLIE_NO_WAL"] = "1"

from dontlie import privacy

SAMPLE_WITH_SECRETS = (
    "Subject: incident 2026-07-24\n"
    "From: alice@corp.example\n"
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345\n"
    "Key: sk-abcdefghijklmnopqrstuvwxyz\n"
    "AWS: AKIAABCDEFGHIJKLMNOP\n"
    "SSN: 123-45-6789\n"
    "Phone: +14155551212\n"
    "Card: 4111 1111 1111 1111\n"
    "Server: http://10.0.0.5\n"
    "Body: nothing else interesting\n"
)

SAMPLE_PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIBOgIBAAJBALR9vQyqQGqfakefakefakefakefakefakefakefakefakefakefak=\n"
    "-----END RSA PRIVATE KEY-----\n"
)


class DetectorRegistryTest(unittest.TestCase):
    def test_default_registry_detects_known_secrets(self) -> None:
        registry = privacy.default_registry()
        detections = registry.detect(SAMPLE_WITH_SECRETS)
        detector_ids = sorted({d.detector for d in detections})
        # These detectors are non-overlapping and the sample
        # contains one of each.
        for expected in (
            "openai_api_key",
            "bearer_token",
            "aws_access_key",
            "us_ssn",
            "phone_e164",
            "credit_card",
            "ipv4",
            "email",
        ):
            self.assertIn(expected, detector_ids, f"missing {expected} in {detector_ids}")

    def test_pem_private_key_block_detected(self) -> None:
        registry = privacy.default_registry()
        detections = registry.detect(SAMPLE_PEM)
        self.assertTrue(
            any(d.detector == "private_key_block" for d in detections),
            "PEM private key block was not detected",
        )

    def test_overlap_resolution_picks_first_detector(self) -> None:
        registry = privacy.default_registry()
        # ``openai_api_key`` is registered before ``bearer_token``,
        # so its hit at offset 7 claims the span and the wider
        # ``bearer_token`` match (which starts at 0) is dropped
        # as overlapping.
        text = "Bearer sk-abcdefghijklmnopqrstuvwxyz0123"
        detections = registry.detect(text)
        detectors = [d.detector for d in detections]
        self.assertEqual(detectors, ["openai_api_key"])

    def test_no_false_positive_on_clean_text(self) -> None:
        registry = privacy.default_registry()
        detections = registry.detect("just a plain note with no secrets at all")
        self.assertEqual(list(detections), [])


class EvidenceModesTest(unittest.TestCase):
    def test_fingerprint_mode_is_text_free(self) -> None:
        evidence = privacy.build_evidence(
            SAMPLE_WITH_SECRETS, mode="fingerprint"
        )
        self.assertEqual(evidence.mode, "fingerprint")
        self.assertIsNone(evidence.text)
        assert evidence.fingerprint is not None  # type narrow for pyright
        self.assertTrue(evidence.fingerprint.startswith("sha256:"))
        # No secret strings may leak through a fingerprint artifact.
        blob = evidence.to_json()
        for needle in ("sk-", "AKIA", "Bearer", "123-45-6789", "@corp.example"):
            self.assertNotIn(needle, blob)

    def test_redacted_mode_replaces_secrets(self) -> None:
        evidence = privacy.build_evidence(
            SAMPLE_WITH_SECRETS, mode="redacted"
        )
        self.assertEqual(evidence.mode, "redacted")
        assert evidence.text is not None
        self.assertNotIn("sk-abcdefghijklmnopqrstuvwxyz", evidence.text)
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", evidence.text)
        self.assertIn("[PARTIAL:", evidence.text)
        # The warning is mandatory: we never claim redaction is complete.
        self.assertTrue(
            any("heuristic" in w for w in evidence.warnings),
            "redacted evidence must carry a heuristic warning",
        )

    def test_forensic_mode_preserves_original(self) -> None:
        evidence = privacy.build_evidence(
            SAMPLE_WITH_SECRETS, mode="forensic"
        )
        self.assertEqual(evidence.mode, "forensic")
        self.assertEqual(evidence.text, SAMPLE_WITH_SECRETS)
        self.assertIsNotNone(evidence.fingerprint)
        self.assertTrue(evidence.redactions)

    def test_invalid_mode_rejected_at_type_level(self) -> None:
        # EvidenceMode is a Literal type; passing a non-literal
        # should fail mypy/pyright. At runtime we only exercise the
        # documented modes here.
        for mode in ("fingerprint", "redacted", "forensic"):
            evidence = privacy.build_evidence("hi", mode=mode)  # type: ignore[arg-type]
            self.assertEqual(evidence.mode, mode)

    def test_text_digest_is_stable_sha256(self) -> None:
        digest_a = privacy.text_digest("hello")
        digest_b = privacy.text_digest("hello")
        self.assertEqual(digest_a, digest_b)
        self.assertEqual(len(digest_a), 64)

    def test_determinism_two_runs_match(self) -> None:
        a = privacy.build_evidence(SAMPLE_WITH_SECRETS, mode="redacted")
        b = privacy.build_evidence(SAMPLE_WITH_SECRETS, mode="redacted")
        # generated_at and all other fields must match because
        # we use a deterministic timestamp.
        self.assertEqual(a.to_json(), b.to_json())


class RedactionTextTest(unittest.TestCase):
    def test_redact_text_preserves_offsets(self) -> None:
        detections = privacy.detect("contact alice@corp.example today")
        text = privacy.redact_text("contact alice@corp.example today", detections)
        self.assertIn("[PARTIAL:email:", text)
        self.assertTrue(text.startswith("contact "))
        self.assertTrue(text.endswith(" today"))

    def test_redact_text_handles_empty_text(self) -> None:
        self.assertEqual(privacy.redact_text("", ()), "")

    def test_redact_text_skips_overlapping_detections(self) -> None:
        # If a caller hands us overlapping detections, the second
        # is dropped so the function is linear and deterministic.
        first = privacy.Detection(
            detector="x",
            label="x",
            start=0,
            end=10,
            text="0123456789",
            digest_sha256="a" * 64,
        )
        second = privacy.Detection(
            detector="y",
            label="y",
            start=5,
            end=15,
            text="56789abcde",
            digest_sha256="b" * 64,
        )
        out = privacy.redact_text("0123456789ABCDEF", (first, second))
        self.assertEqual(out.count("[PARTIAL:"), 1)
        self.assertIn("ABCDEF", out)


class ForensicDiffTest(unittest.TestCase):
    def test_diff_summary_agrees_with_redact(self) -> None:
        original = "sk-abcdefghijklmnopqrstuvwxyz and alice@corp.example"
        redacted = privacy.build_evidence(original, mode="redacted")
        summary = privacy.forensic_diff_summary(original, redacted)
        self.assertTrue(summary["byte_equal"])
        self.assertEqual(summary["original_digest"], privacy.text_digest(original))
        self.assertEqual(
            summary["redacted_digest"],
            privacy.text_digest(redacted.text or ""),
        )
        self.assertEqual(summary["redaction_count"], 2)
        self.assertEqual(set(summary["detectors"]), {"openai_api_key", "email"})

    def test_diff_summary_rejects_wrong_mode(self) -> None:
        forensic = privacy.build_evidence("hi", mode="forensic")
        with self.assertRaises(privacy.PrivacyError):
            privacy.forensic_diff_summary("hi", forensic)


class VerifyEvidenceTest(unittest.TestCase):
    def test_round_trip(self) -> None:
        original = privacy.build_evidence("sk-test-1234567890abcdefghij", mode="redacted")
        parsed = privacy.verify_evidence(original.to_json())
        self.assertEqual(parsed.mode, "redacted")
        self.assertEqual(parsed.text_digest_sha256, original.text_digest_sha256)
        self.assertEqual(parsed.text, original.text)
        self.assertEqual(len(parsed.redactions), len(original.redactions))

    def test_rejects_garbage(self) -> None:
        with self.assertRaises(privacy.PrivacyError):
            privacy.verify_evidence("not json")
        with self.assertRaises(privacy.PrivacyError):
            privacy.verify_evidence(json.dumps({"format": "other"}))

    def test_rejects_unknown_format_version(self) -> None:
        payload = json.dumps(
            {
                "format": "dontlie-evidence",
                "format_version": 99,
                "mode": "fingerprint",
            }
        )
        with self.assertRaises(privacy.PrivacyError):
            privacy.verify_evidence(payload)


class InlineSecretProbeTest(unittest.TestCase):
    def test_detect_inline_secrets_returns_stable_unique_list(self) -> None:
        # Stability means: two calls produce the same list, and the
        # list contains each detector id at most once.
        first = privacy.detect_inline_secrets(SAMPLE_WITH_SECRETS)
        second = privacy.detect_inline_secrets(SAMPLE_WITH_SECRETS)
        self.assertEqual(first, second)
        self.assertEqual(len(first), len(set(first)))
        self.assertIn("openai_api_key", first)

    def test_custom_detector_registration(self) -> None:
        registry = privacy.DetectorRegistry()
        registry.register("custom_token", "Custom token", r"(?P<custom_token>CUST-[A-Z0-9]{6})")
        hits = registry.detect("token is CUST-AB12CD here")
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0].detector, "custom_token")
        self.assertEqual(hits[0].label, "Custom token")

    def test_register_rejects_duplicate(self) -> None:
        registry = privacy.DetectorRegistry()
        registry.register("a", "A", r"(?P<a>A)")
        with self.assertRaises(privacy.PrivacyError):
            registry.register("a", "A2", r"(?P<a2>A)")

    def test_register_rejects_missing_named_group(self) -> None:
        registry = privacy.DetectorRegistry()
        with self.assertRaises(privacy.PrivacyError):
            registry.register("bad", "bad", r"abc")

    def test_empty_text_yields_no_detections(self) -> None:
        self.assertEqual(privacy.detect(""), ())


class ConveniencePayloadsTest(unittest.TestCase):
    def test_convenience_payloads_parse_back(self) -> None:
        text = "hello sk-abcdefghijklmnopqrstuvwxyz world"
        for payload in (
            privacy.fingerprint_payload(text),
            privacy.redacted_payload(text),
            privacy.forensic_payload(text),
        ):
            evidence = privacy.verify_evidence(payload)
            self.assertEqual(evidence.text_digest_sha256, privacy.text_digest(text))


if __name__ == "__main__":
    unittest.main()
