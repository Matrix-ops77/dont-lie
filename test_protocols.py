"""Provider protocol conformance and proxy integration tests."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from dontlie import cli, protocols, proxy

FIXTURES = Path(__file__).parent / "interop" / "fixtures"


class AdapterConformanceTest(unittest.TestCase):
    def test_versioned_registry_and_configurable_auth_path(self) -> None:
        self.assertIs(
            protocols.get_adapter("openai-chat-completions@1"),
            protocols.OPENAI_CHAT,
        )
        self.assertIs(protocols.get_adapter("anthropic"), protocols.ANTHROPIC_MESSAGES)
        self.assertEqual(
            protocols.OPENAI_CHAT.auth_headers("secret")["Authorization"],
            "Bearer secret",
        )
        anthropic_headers = protocols.ANTHROPIC_MESSAGES.auth_headers("secret")
        self.assertEqual(anthropic_headers["x-api-key"], "secret")
        self.assertEqual(anthropic_headers["anthropic-version"], "2023-06-01")

        config = protocols.AuthConfig(
            header_name="Authorization",
            scheme="Token",
            path="/gateway/messages",
            extra_headers={"anthropic-version": "2024-01-01"},
        )
        self.assertEqual(
            protocols.ANTHROPIC_MESSAGES.request_path(config),
            "/gateway/messages",
        )
        configured = protocols.ANTHROPIC_MESSAGES.auth_headers("key", config)
        self.assertEqual(configured["Authorization"], "Token key")
        self.assertEqual(configured["anthropic-version"], "2024-01-01")

    def test_anthropic_validation_enforces_native_required_fields(self) -> None:
        valid = {
            "model": "claude-fixture",
            "max_tokens": 32,
            "messages": [{"role": "user", "content": "hello"}],
        }
        self.assertEqual(
            protocols.ANTHROPIC_MESSAGES.validate_request(valid),
            (valid, None),
        )
        _, missing_tokens = protocols.ANTHROPIC_MESSAGES.validate_request(
            {"model": "claude", "messages": []}
        )
        self.assertIn("max_tokens", missing_tokens or "")
        _, system_role = protocols.ANTHROPIC_MESSAGES.validate_request(
            {
                "model": "claude",
                "max_tokens": 1,
                "messages": [{"role": "system", "content": "no"}],
            }
        )
        self.assertIn("user", system_role or "")

    def test_native_json_responses_extract_text(self) -> None:
        openai = (FIXTURES / "openai_response.json").read_bytes()
        anthropic = (FIXTURES / "anthropic_response.json").read_bytes()
        self.assertEqual(
            protocols.OPENAI_CHAT.response_text(openai, streamed=False),
            "Hello world",
        )
        self.assertEqual(
            protocols.ANTHROPIC_MESSAGES.response_text(
                anthropic,
                streamed=False,
            ),
            "Hello world",
        )

    def test_native_streams_survive_single_byte_chunking(self) -> None:
        for fixture, adapter in (
            ("openai_stream.sse", protocols.OPENAI_CHAT),
            ("anthropic_stream.sse", protocols.ANTHROPIC_MESSAGES),
        ):
            raw = (FIXTURES / fixture).read_bytes()
            decoder = protocols.SSEDecoder()
            events = []
            for byte in raw:
                events.extend(decoder.feed(bytes([byte])))
            events.extend(decoder.finish())
            self.assertGreater(len(events), 2)
            self.assertEqual(adapter.response_text(raw, streamed=True), "Hello world")

    def test_sse_decoder_handles_fragmented_crlf_boundaries(self) -> None:
        raw = b"event: delta\r\ndata: one\r\n\r\nevent: done\r\ndata: two\r\n\r\n"
        decoder = protocols.SSEDecoder()
        events = []
        for byte in raw:
            events.extend(decoder.feed(bytes([byte])))
        events.extend(decoder.finish())
        self.assertEqual(
            events,
            [
                protocols.SSEEvent("delta", "one"),
                protocols.SSEEvent("done", "two"),
            ],
        )

    def test_cli_exposes_native_protocol_and_transport_overrides(self) -> None:
        args = cli.build_parser().parse_args(
            [
                "proxy",
                "--protocol",
                "anthropic",
                "--upstream-path",
                "/gateway/messages",
                "--auth-header",
                "Authorization",
                "--auth-scheme",
                "Token",
                "--anthropic-version",
                "2024-01-01",
            ]
        )
        self.assertEqual(args.protocol, "anthropic")
        self.assertEqual(args.upstream_path, "/gateway/messages")
        self.assertEqual(args.auth_header, "Authorization")
        self.assertEqual(args.auth_scheme, "Token")
        self.assertEqual(args.anthropic_version, "2024-01-01")

    def test_unknown_adapter_is_explicit(self) -> None:
        with self.assertRaisesRegex(protocols.ProtocolError, "unknown protocol"):
            protocols.get_adapter("mystery")


class ProtocolProxyIntegrationTest(unittest.TestCase):
    def test_anthropic_status_error_is_passed_through_and_receipted(self) -> None:
        body = {
            "model": "claude-fixture",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hello"}],
        }
        error = b'{"type":"error","error":{"type":"rate_limit_error","message":"slow"}}'
        forward = AsyncMock(
            return_value=(429, {"content-type": "application/json"}, error)
        )
        with (
            patch.object(proxy, "_forward_and_capture", forward),
            patch.object(proxy.storage, "append") as append,
        ):
            result = proxy.handle_protocol_completion(
                body,
                "anthropic-key",
                protocols.ANTHROPIC_MESSAGES,
                upstream_base_url="https://api.anthropic.com",
            )

        self.assertEqual(result["_dontlie_passthrough_status"], 429)
        self.assertEqual(result["_dontlie_passthrough_body_bytes"], error)
        self.assertIn("rate_limit_error", append.call_args.kwargs["response"])
        self.assertEqual(
            append.call_args.kwargs["extra"]["endpoint"],
            "/v1/messages",
        )
        self.assertEqual(
            forward.await_args.kwargs["protocol_adapter"],
            protocols.ANTHROPIC_MESSAGES,
        )

    def test_anthropic_success_remains_native_json(self) -> None:
        body = {
            "model": "claude-fixture",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hello"}],
        }
        response = (FIXTURES / "anthropic_response.json").read_bytes()
        with (
            patch.object(
                proxy,
                "_forward_and_capture",
                AsyncMock(
                    return_value=(
                        200,
                        {"content-type": "application/json"},
                        response,
                    )
                ),
            ),
            patch.object(proxy.storage, "append"),
        ):
            result = proxy.handle_protocol_completion(
                body,
                "key",
                protocols.ANTHROPIC_MESSAGES,
            )
        self.assertEqual(result["type"], "message")
        self.assertEqual(result["content"][0]["text"], "Hello")


class ProtocolStreamingIntegrationTest(unittest.IsolatedAsyncioTestCase):
    async def test_anthropic_stream_is_forwarded_unchanged_and_receipted(self) -> None:
        body = {
            "model": "claude-fixture",
            "max_tokens": 16,
            "messages": [{"role": "user", "content": "hello"}],
            "stream": True,
        }
        raw = (FIXTURES / "anthropic_stream.sse").read_bytes()
        chunks = [raw[:31], raw[31:117], raw[117:]]
        written: list[bytes] = []
        flush_count = 0

        async def fake_stream(method, url, headers, payload, on_chunk, on_start=None):
            self.assertEqual(method, "POST")
            self.assertEqual(url, "https://api.anthropic.com/v1/messages")
            self.assertEqual(headers["x-api-key"], "key")
            self.assertEqual(headers["anthropic-version"], "2023-06-01")
            self.assertEqual(payload, body)
            if on_start:
                await on_start(200, {"content-type": "text/event-stream"})
            for chunk in chunks:
                await on_chunk(chunk)
            return 200, {"content-type": "text/event-stream"}, len(raw)

        async def write(chunk: bytes) -> None:
            written.append(chunk)

        async def flush() -> None:
            nonlocal flush_count
            flush_count += 1

        with (
            patch.object(proxy, "_stream_response", side_effect=fake_stream),
            patch.object(proxy.storage, "append") as append,
        ):
            result = await proxy.stream_protocol_to_client(
                body,
                "key",
                protocols.ANTHROPIC_MESSAGES,
                write,
                flush,
                upstream_base_url="https://api.anthropic.com",
            )

        self.assertEqual(b"".join(written), raw)
        self.assertEqual(flush_count, len(chunks))
        self.assertEqual(result["status"], 200)
        self.assertEqual(append.call_args.kwargs["response"], "Hello world")
        self.assertIn(
            "protocol:anthropic-messages@1",
            append.call_args.kwargs["tags"],
        )


if __name__ == "__main__":
    unittest.main()
