"""Versioned provider protocols and explicit interoperability converters.

Adapters preserve each provider's native wire format. They do not translate
responses in flight; they provide validation, auth/path configuration,
canonical receipt input, and text extraction for signed receipts.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from abc import ABC, abstractmethod
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any, ClassVar

JSONDict = dict[str, Any]


class ProtocolError(ValueError):
    """Raised when a protocol name, request, or conversion is unsupported."""


@dataclass(frozen=True)
class AuthConfig:
    """Optional auth/path overrides for non-standard compatible providers."""

    header_name: str | None = None
    scheme: str | None = None
    path: str | None = None
    extra_headers: Mapping[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class SSEEvent:
    """One parsed Server-Sent Event."""

    event: str | None
    data: str
    event_id: str | None = None


class SSEDecoder:
    """Incremental SSE decoder that tolerates arbitrary transport chunking."""

    def __init__(self) -> None:
        self._buffer = b""

    def feed(self, chunk: bytes) -> list[SSEEvent]:
        self._buffer += chunk
        events: list[SSEEvent] = []
        while True:
            boundary = _next_sse_boundary(self._buffer)
            if boundary is None:
                break
            index, width = boundary
            frame, self._buffer = (
                self._buffer[:index],
                self._buffer[index + width :],
            )
            event = _parse_sse_frame(frame)
            if event is not None:
                events.append(event)
        return events

    def finish(self) -> list[SSEEvent]:
        if not self._buffer.strip():
            self._buffer = b""
            return []
        frame, self._buffer = self._buffer, b""
        event = _parse_sse_frame(frame)
        return [event] if event is not None else []


def _next_sse_boundary(data: bytes) -> tuple[int, int] | None:
    matches = [
        (index, len(delimiter))
        for delimiter in (b"\r\n\r\n", b"\n\n", b"\r\r")
        if (index := data.find(delimiter)) >= 0
    ]
    return min(matches) if matches else None


def _parse_sse_frame(frame: bytes) -> SSEEvent | None:
    event_type: str | None = None
    event_id: str | None = None
    data: list[str] = []
    normalized = frame.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    for raw_line in normalized.split(b"\n"):
        line = raw_line.decode("utf-8", errors="replace")
        if not line or line.startswith(":"):
            continue
        field_name, separator, value = line.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field_name == "event":
            event_type = value
        elif field_name == "id":
            event_id = value
        elif field_name == "data":
            data.append(value)
    if not data and event_type is None and event_id is None:
        return None
    return SSEEvent(event=event_type, data="\n".join(data), event_id=event_id)


def decode_sse(data: bytes) -> list[SSEEvent]:
    decoder = SSEDecoder()
    return [*decoder.feed(data), *decoder.finish()]


class ProtocolAdapter(ABC):
    """Provider-native, versioned request/response contract."""

    name: ClassVar[str]
    adapter_version: ClassVar[str] = "1"
    default_path: ClassVar[str]
    default_auth_header: ClassVar[str]
    default_auth_scheme: ClassVar[str | None]

    @property
    def identifier(self) -> str:
        return f"{self.name}@{self.adapter_version}"

    def request_path(self, config: AuthConfig | None = None) -> str:
        path = config.path if config and config.path else self.default_path
        return "/" + path.lstrip("/")

    def auth_headers(
        self,
        api_key: str,
        config: AuthConfig | None = None,
    ) -> dict[str, str]:
        key = api_key.strip()
        if not key:
            raise ProtocolError(f"{self.name} API key must not be empty")
        header = (
            config.header_name
            if config and config.header_name
            else self.default_auth_header
        )
        scheme = (
            config.scheme
            if config and config.scheme is not None
            else self.default_auth_scheme
        )
        value = f"{scheme} {key}" if scheme else key
        headers = {"content-type": "application/json", header: value}
        if config:
            headers.update(config.extra_headers)
        return headers

    def validate_request(self, body: object) -> tuple[JSONDict | None, str | None]:
        if not isinstance(body, dict):
            return None, "request body must be a JSON object"
        if not isinstance(body.get("model"), str) or not body["model"]:
            return None, "missing or empty 'model' field"
        return body, None

    def canonical_request(self, body: Mapping[str, Any]) -> str:
        return json.dumps(
            body,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )

    def model(self, body: Mapping[str, Any]) -> str:
        return str(body.get("model", "unknown"))

    def is_stream(self, body: Mapping[str, Any]) -> bool:
        return body.get("stream") is True

    def tags(self, body: Mapping[str, Any]) -> list[str]:
        tags = [f"protocol:{self.identifier}"]
        if self.is_stream(body):
            tags.append("stream")
        if body.get("tools"):
            tags.append("tools")
        return tags

    @abstractmethod
    def response_text(self, response: bytes, *, streamed: bool) -> str:
        """Extract assistant text without changing the native response."""


class OpenAIChatCompletionsAdapter(ProtocolAdapter):
    name = "openai-chat-completions"
    default_path = "/v1/chat/completions"
    default_auth_header = "Authorization"
    default_auth_scheme = "Bearer"

    def validate_request(self, body: object) -> tuple[JSONDict | None, str | None]:
        parsed, error = super().validate_request(body)
        if error or parsed is None:
            return None, error
        messages = parsed.get("messages")
        if messages is not None and not isinstance(messages, list):
            return None, "'messages' must be a list"
        return parsed, None

    def response_text(self, response: bytes, *, streamed: bool) -> str:
        if streamed:
            parts: list[str] = []
            for event in decode_sse(response):
                if event.data in {"", "[DONE]"}:
                    continue
                payload = _json_object(event.data)
                if payload is None:
                    continue
                try:
                    delta = payload["choices"][0]["delta"]["content"]
                except (KeyError, IndexError, TypeError):
                    continue
                if isinstance(delta, str):
                    parts.append(delta)
            return "".join(parts)
        payload = _json_bytes_object(response)
        if payload is None:
            return response.decode("utf-8", errors="replace")
        try:
            content = payload["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError):
            return json.dumps(payload, sort_keys=True)
        return _content_text(content)


class AnthropicMessagesAdapter(ProtocolAdapter):
    name = "anthropic-messages"
    default_path = "/v1/messages"
    default_auth_header = "x-api-key"
    default_auth_scheme = None
    anthropic_version = "2023-06-01"

    def auth_headers(
        self,
        api_key: str,
        config: AuthConfig | None = None,
    ) -> dict[str, str]:
        headers = super().auth_headers(api_key, config)
        headers.setdefault("anthropic-version", self.anthropic_version)
        return headers

    def validate_request(self, body: object) -> tuple[JSONDict | None, str | None]:
        parsed, error = super().validate_request(body)
        if error or parsed is None:
            return None, error
        messages = parsed.get("messages")
        if not isinstance(messages, list):
            return None, "'messages' must be a list"
        max_tokens = parsed.get("max_tokens")
        if (
            isinstance(max_tokens, bool)
            or not isinstance(max_tokens, int)
            or max_tokens <= 0
        ):
            return None, "'max_tokens' must be a positive integer"
        for index, message in enumerate(messages):
            if not isinstance(message, dict):
                return None, f"messages[{index}] must be an object"
            if message.get("role") not in {"user", "assistant"}:
                return None, (f"messages[{index}].role must be 'user' or 'assistant'")
            if not isinstance(message.get("content"), (str, list)):
                return None, f"messages[{index}].content must be text or blocks"
        system = parsed.get("system")
        if system is not None and not isinstance(system, (str, list)):
            return None, "'system' must be text or content blocks"
        return parsed, None

    def response_text(self, response: bytes, *, streamed: bool) -> str:
        if streamed:
            parts: list[str] = []
            for event in decode_sse(response):
                payload = _json_object(event.data)
                if payload is None:
                    continue
                delta = payload.get("delta")
                if (
                    payload.get("type") == "content_block_delta"
                    and isinstance(delta, dict)
                    and delta.get("type") == "text_delta"
                    and isinstance(delta.get("text"), str)
                ):
                    parts.append(delta["text"])
            return "".join(parts)
        payload = _json_bytes_object(response)
        if payload is None:
            return response.decode("utf-8", errors="replace")
        if "content" not in payload:
            return json.dumps(payload, sort_keys=True)
        return _content_text(payload.get("content", []))


OPENAI_CHAT = OpenAIChatCompletionsAdapter()
ANTHROPIC_MESSAGES = AnthropicMessagesAdapter()
_ADAPTERS: dict[str, ProtocolAdapter] = {
    "openai": OPENAI_CHAT,
    "openai-chat-completions": OPENAI_CHAT,
    OPENAI_CHAT.identifier: OPENAI_CHAT,
    "anthropic": ANTHROPIC_MESSAGES,
    "anthropic-messages": ANTHROPIC_MESSAGES,
    ANTHROPIC_MESSAGES.identifier: ANTHROPIC_MESSAGES,
}


def get_adapter(name: str) -> ProtocolAdapter:
    try:
        return _ADAPTERS[name.strip().lower()]
    except KeyError as exc:
        supported = ", ".join(
            sorted({adapter.identifier for adapter in _ADAPTERS.values()})
        )
        raise ProtocolError(
            f"unknown protocol {name!r}; supported adapters: {supported}"
        ) from exc


def _json_object(value: str) -> JSONDict | None:
    try:
        parsed = json.loads(value)
    except json.JSONDecodeError:
        return None
    return parsed if isinstance(parsed, dict) else None


def _json_bytes_object(value: bytes) -> JSONDict | None:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def _content_text(content: object) -> str:
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return json.dumps(content, sort_keys=True)
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif (
            isinstance(block, dict)
            and block.get("type") == "text"
            and isinstance(block.get("text"), str)
        ):
            parts.append(block["text"])
    return "".join(parts)


@dataclass(frozen=True)
class ConversionResult:
    """A conversion plus a machine-readable disclosure of what changed."""

    payload: JSONDict
    transformations: tuple[str, ...]
    limitations: tuple[str, ...] = ()


def openai_to_anthropic_request(
    body: Mapping[str, Any],
    *,
    default_max_tokens: int | None = None,
) -> ConversionResult:
    parsed, error = OPENAI_CHAT.validate_request(dict(body))
    if error or parsed is None:
        raise ProtocolError(error or "invalid OpenAI request")
    messages = parsed.get("messages", [])
    if not isinstance(messages, list):
        raise ProtocolError("'messages' must be a list")
    converted_messages: list[JSONDict] = []
    system_parts: list[str] = []
    transformations = ["wire protocol: OpenAI Chat Completions -> Anthropic Messages"]
    for index, message in enumerate(messages):
        if not isinstance(message, dict):
            raise ProtocolError(f"messages[{index}] must be an object")
        role = message.get("role")
        content = message.get("content")
        if _contains_tool_blocks(message):
            raise ProtocolError(
                "OpenAI tool call/result messages require an explicit tool mapper"
            )
        if role == "system":
            if not isinstance(content, str):
                raise ProtocolError("only text OpenAI system messages are convertible")
            system_parts.append(content)
        elif role in {"user", "assistant"}:
            if not isinstance(content, str):
                raise ProtocolError(
                    "only text OpenAI user/assistant messages are convertible"
                )
            converted_messages.append({"role": role, "content": content})
        else:
            raise ProtocolError(f"OpenAI role {role!r} is not losslessly convertible")

    max_tokens = parsed.get("max_completion_tokens", parsed.get("max_tokens"))
    if max_tokens is None:
        if default_max_tokens is None:
            raise ProtocolError(
                "Anthropic requires max_tokens; pass default_max_tokens explicitly"
            )
        max_tokens = default_max_tokens
        transformations.append("max_tokens: caller-supplied default inserted")

    output: JSONDict = {
        "model": parsed["model"],
        "messages": converted_messages,
        "max_tokens": max_tokens,
    }
    if system_parts:
        output["system"] = "\n\n".join(system_parts)
        transformations.append("system-role messages moved to top-level system")
    for source, target in (
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stream", "stream"),
    ):
        if source in parsed:
            output[target] = parsed[source]
    if "stop" in parsed:
        stop = parsed["stop"]
        if isinstance(stop, str):
            output["stop_sequences"] = [stop]
            transformations.append("single stop string wrapped as stop_sequences")
        elif isinstance(stop, list) and all(isinstance(item, str) for item in stop):
            output["stop_sequences"] = stop
        else:
            raise ProtocolError("OpenAI stop must be text or a list of text")
    if "tools" in parsed:
        output["tools"] = _openai_tools_to_anthropic(parsed["tools"])
        transformations.append("tool schemas: function.parameters -> input_schema")
    _, target_error = ANTHROPIC_MESSAGES.validate_request(output)
    if target_error is not None:
        raise ProtocolError(f"converted Anthropic request is invalid: {target_error}")
    return ConversionResult(payload=output, transformations=tuple(transformations))


def anthropic_to_openai_request(body: Mapping[str, Any]) -> ConversionResult:
    parsed, error = ANTHROPIC_MESSAGES.validate_request(dict(body))
    if error or parsed is None:
        raise ProtocolError(error or "invalid Anthropic request")
    messages: list[JSONDict] = []
    transformations = ["wire protocol: Anthropic Messages -> OpenAI Chat Completions"]
    if "system" in parsed:
        system = parsed["system"]
        if not isinstance(system, str):
            raise ProtocolError("only text Anthropic system prompts are convertible")
        messages.append({"role": "system", "content": system})
        transformations.append("top-level system moved to system-role message")
    for index, message in enumerate(parsed["messages"]):
        if not isinstance(message, dict):
            raise ProtocolError(f"messages[{index}] must be an object")
        content = message.get("content")
        if not isinstance(content, str):
            if not isinstance(content, list) or not all(
                isinstance(block, dict)
                and block.get("type") == "text"
                and isinstance(block.get("text"), str)
                for block in content
            ):
                raise ProtocolError(
                    "Anthropic non-text content/tool blocks require an explicit mapper"
                )
            content = "".join(str(block["text"]) for block in content)
            transformations.append("text content blocks flattened to one string")
        messages.append({"role": message["role"], "content": content})
    output: JSONDict = {
        "model": parsed["model"],
        "messages": messages,
        "max_tokens": parsed["max_tokens"],
    }
    for source, target in (
        ("temperature", "temperature"),
        ("top_p", "top_p"),
        ("stream", "stream"),
        ("stop_sequences", "stop"),
    ):
        if source in parsed:
            output[target] = parsed[source]
    if "tools" in parsed:
        output["tools"] = _anthropic_tools_to_openai(parsed["tools"])
        transformations.append("tool schemas: input_schema -> function.parameters")
    return ConversionResult(payload=output, transformations=tuple(transformations))


def _contains_tool_blocks(message: Mapping[str, Any]) -> bool:
    return bool(message.get("tool_calls")) or message.get("role") == "tool"


def _openai_tools_to_anthropic(tools: object) -> list[JSONDict]:
    if not isinstance(tools, list):
        raise ProtocolError("OpenAI tools must be a list")
    result: list[JSONDict] = []
    for tool in tools:
        if not isinstance(tool, dict) or tool.get("type") != "function":
            raise ProtocolError("only OpenAI function tools are convertible")
        function = tool.get("function")
        if not isinstance(function, dict) or not isinstance(function.get("name"), str):
            raise ProtocolError("OpenAI function tool must have a name")
        converted = {
            "name": function["name"],
            "input_schema": function.get("parameters", {"type": "object"}),
        }
        if "description" in function:
            converted["description"] = function["description"]
        result.append(converted)
    return result


def _anthropic_tools_to_openai(tools: object) -> list[JSONDict]:
    if not isinstance(tools, list):
        raise ProtocolError("Anthropic tools must be a list")
    result: list[JSONDict] = []
    for tool in tools:
        if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
            raise ProtocolError("Anthropic tool must have a name")
        function = {
            "name": tool["name"],
            "parameters": tool.get("input_schema", {"type": "object"}),
        }
        if "description" in tool:
            function["description"] = tool["description"]
        result.append({"type": "function", "function": function})
    return result


def to_obsigna_compat(source_receipt: Mapping[str, Any]) -> ConversionResult:
    """Project a Don't-Lie receipt into an explicitly unsigned AR draft.

    The original receipt is retained byte-for-data, including its signature.
    That signature covers Don't-Lie's canonical payload and is never placed in
    ``proof``, because it cannot verify over an RFC 8785 Agent Receipt.
    """
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
    }
    missing = sorted(required.difference(source_receipt))
    if missing:
        raise ProtocolError(f"Don't-Lie receipt missing fields: {', '.join(missing)}")
    receipt_id = int(source_receipt["id"])
    payload_hash = str(source_receipt["payload_sha256"])
    action_uuid = uuid.uuid5(uuid.NAMESPACE_URL, f"dontlie:{payload_hash}")
    prompt_hash = hashlib.sha256(
        json.dumps(
            str(source_receipt["prompt"]),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    response_hash = hashlib.sha256(
        json.dumps(
            str(source_receipt["response"]),
            ensure_ascii=False,
            separators=(",", ":"),
        ).encode("utf-8")
    ).hexdigest()
    extra = source_receipt.get("extra")
    status_code = extra.get("status") if isinstance(extra, dict) else None
    if not isinstance(status_code, int):
        outcome_status = "pending"
    elif 200 <= status_code < 300:
        outcome_status = "success"
    else:
        outcome_status = "failure"
    draft: JSONDict = {
        "@context": [
            "https://www.w3.org/ns/credentials/v2",
            "https://agentreceipts.ai/context/v2",
        ],
        "id": f"urn:receipt:{action_uuid}",
        "type": ["VerifiableCredential", "AgentReceipt"],
        "version": "0.5.0",
        "issuer": {
            "id": f"urn:dontlie:key:{source_receipt['key_id']}",
            "type": "AIAgent",
            "name": "Don't-Lie proxy",
            "model": source_receipt["model"],
        },
        "issuanceDate": source_receipt["timestamp"],
        "credentialSubject": {
            "principal": {"id": "urn:dontlie:principal:undisclosed"},
            "action": {
                "id": f"act_{action_uuid}",
                "type": "ai.model.invoke",
                "risk_level": "low",
                "parameters_hash": f"sha256:{prompt_hash}",
                "timestamp": source_receipt["timestamp"],
            },
            "outcome": {
                "status": outcome_status,
                "response_hash": f"sha256:{response_hash}",
            },
            "chain": {
                "sequence": receipt_id,
                "previous_receipt_hash": None,
                "chain_id": "chain_dontlie_export",
            },
        },
    }
    envelope: JSONDict = {
        "format": "dontlie-obsigna-compat",
        "version": "1.0",
        "signature_status": {
            "source_preserved": True,
            "agent_receipt_draft_signed": False,
            "reason": (
                "source signature covers the Don't-Lie canonical payload, "
                "not the transformed RFC 8785 Agent Receipt draft"
            ),
        },
        "source_receipt": dict(source_receipt),
        "agent_receipt_draft": draft,
    }
    return ConversionResult(
        payload=envelope,
        transformations=(
            "Don't-Lie receipt projected to Agent Receipts 0.5.0 field names",
            "prompt and response replaced by sha256-prefixed content hashes",
            "original receipt and signature retained under source_receipt",
        ),
        limitations=(
            "agent_receipt_draft is unsigned and must not be accepted as a Verifiable Credential",
            "Don't-Lie parent_id has no parent receipt hash, so previous_receipt_hash is unknown",
            "principal, authorization, intent, target, and reversibility are unavailable",
            "ai.model.invoke taxonomy compatibility must be checked against the target Obsigna version",
        ),
    )


def convert_receipts_to_obsigna_compat(
    receipts: Iterable[Mapping[str, Any]],
) -> list[ConversionResult]:
    return [to_obsigna_compat(receipt) for receipt in receipts]
