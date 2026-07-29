"""Explicit request and receipt compatibility conversion tests."""

from __future__ import annotations

import json
import unittest
from pathlib import Path

from dontlie import protocols

FIXTURES = Path(__file__).parent / "interop" / "fixtures"


class RequestConversionTest(unittest.TestCase):
    def test_openai_to_anthropic_matches_deterministic_fixture(self) -> None:
        source = {
            "model": "claude-fixture",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user", "content": "Hello"},
            ],
            "max_tokens": 128,
            "temperature": 0.2,
            "stop": ["END"],
            "tools": [
                {
                    "type": "function",
                    "function": {
                        "name": "weather",
                        "description": "Look up weather",
                        "parameters": {
                            "type": "object",
                            "properties": {"city": {"type": "string"}},
                            "required": ["city"],
                        },
                    },
                }
            ],
        }
        expected = json.loads(
            (FIXTURES / "openai_to_anthropic_expected.json").read_text()
        )
        converted = protocols.openai_to_anthropic_request(source)
        self.assertEqual(converted.payload, expected)
        self.assertTrue(any("system" in item for item in converted.transformations))

    def test_round_trip_preserves_supported_text_semantics(self) -> None:
        anthropic = {
            "model": "claude-fixture",
            "system": "Be concise.",
            "messages": [{"role": "user", "content": "Hello"}],
            "max_tokens": 128,
            "stream": True,
            "stop_sequences": ["END"],
        }
        openai = protocols.anthropic_to_openai_request(anthropic)
        restored = protocols.openai_to_anthropic_request(openai.payload)
        self.assertEqual(restored.payload, anthropic)

    def test_missing_anthropic_token_limit_is_never_silently_invented(self) -> None:
        with self.assertRaisesRegex(protocols.ProtocolError, "default_max_tokens"):
            protocols.openai_to_anthropic_request(
                {
                    "model": "claude-fixture",
                    "messages": [{"role": "user", "content": "Hello"}],
                }
            )

    def test_non_text_and_tool_results_are_explicitly_rejected(self) -> None:
        with self.assertRaisesRegex(protocols.ProtocolError, "non-text"):
            protocols.anthropic_to_openai_request(
                {
                    "model": "claude-fixture",
                    "max_tokens": 16,
                    "messages": [
                        {
                            "role": "user",
                            "content": [
                                {
                                    "type": "image",
                                    "source": {
                                        "type": "base64",
                                        "media_type": "image/png",
                                        "data": "AA==",
                                    },
                                }
                            ],
                        }
                    ],
                }
            )
        with self.assertRaisesRegex(protocols.ProtocolError, "tool mapper"):
            protocols.openai_to_anthropic_request(
                {
                    "model": "claude-fixture",
                    "max_tokens": 16,
                    "messages": [
                        {"role": "tool", "tool_call_id": "1", "content": "ok"}
                    ],
                }
            )


class ObsignaCompatibilityTest(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt = {
            "id": 7,
            "timestamp": "2026-07-24T12:00:00+00:00",
            "model": "claude-fixture",
            "prompt": '{"messages":[{"content":"hello","role":"user"}]}',
            "response": "Hello",
            "parent_id": 6,
            "key_id": "0123456789abcdef",
            "payload_sha256": "ab" * 32,
            "signature": "source-signature-base64",
            "tags": ["protocol:anthropic-messages@1"],
            "extra": {"status": 200},
        }

    def test_source_signature_is_preserved_but_not_misrepresented(self) -> None:
        converted = protocols.to_obsigna_compat(self.receipt)
        envelope = converted.payload
        self.assertEqual(
            envelope["source_receipt"]["signature"],
            "source-signature-base64",
        )
        self.assertFalse(envelope["signature_status"]["agent_receipt_draft_signed"])
        self.assertNotIn("proof", envelope["agent_receipt_draft"])
        self.assertTrue(
            any("unsigned" in limitation for limitation in converted.limitations)
        )

    def test_projection_is_deterministic_and_labels_missing_chain_hash(self) -> None:
        first = protocols.to_obsigna_compat(self.receipt)
        second = protocols.to_obsigna_compat(dict(self.receipt))
        self.assertEqual(first.payload, second.payload)
        chain = first.payload["agent_receipt_draft"]["credentialSubject"]["chain"]
        self.assertEqual(chain["sequence"], 7)
        self.assertIsNone(chain["previous_receipt_hash"])
        self.assertTrue(
            any("previous_receipt_hash" in item for item in first.limitations)
        )


if __name__ == "__main__":
    unittest.main()
