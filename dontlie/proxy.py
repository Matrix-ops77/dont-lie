"""OpenAI-compatible HTTP proxy that auto-logs every request as a signed receipt.

Usage:

    export DONTLIE_UPSTREAM_API_KEY=sk-real-provider-key
    export DONTLIE_UPSTREAM_BASE_URL=https://api.minimax.io/v1
    dontlie proxy --port 8765
    export OPENAI_BASE_URL=http://127.0.0.1:8765/v1
    export OPENAI_API_KEY=dontlie-local  # only satisfies clients that require it
    # any OpenAI client (openai, langchain, etc.) now flows through us

Streaming (SSE) responses are accumulated before logging so the receipt
contains the full assistant text.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import time
from collections.abc import Awaitable, Callable
from typing import Any

import httpx

from . import protocols, storage

DEFAULT_UPSTREAM_BASE_URL = "https://api.openai.com"
UPSTREAM_BASE_URL_ENV = "DONTLIE_UPSTREAM_BASE_URL"

# Hop-by-hop and framing headers that must never be forwarded. These are
# transport-layer concerns of the inbound HTTP request; the upstream
# provider computes its own values for the outbound leg.
_HOP_BY_HOP_HEADERS = frozenset({
    "host",
    "content-length",
    "connection",
    "keep-alive",
    "transfer-encoding",
    "upgrade",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "trailer",
})

_SECRET_HEADERS = frozenset(
    {"authorization", "api-key", "x-api-key", "x-dontlie-upstream-key"}
)

# Maximum JSON request body we will accept from a local client. 16 MiB is
# large enough for any reasonable chat-completions payload (a 200k-token
# request with multimodal blocks is well under that) while preventing a
# malicious local process from OOM-ing the proxy.
MAX_REQUEST_BYTES = 16 * 1024 * 1024
MAX_RAW_RESPONSE_BYTES = 16 * 1024 * 1024


def resolve_upstream_base_url(explicit: str | None = None) -> str:
    """Resolve the provider URL without reusing the client's OPENAI_BASE_URL.

    OPENAI_BASE_URL points an OpenAI client *at this proxy*. Reusing it for the
    proxy's outbound destination creates a loop (or makes startup depend on the
    order in which a shell exports variables), so the upstream has its own
    namespace.
    """
    return (
        explicit
        or os.environ.get(UPSTREAM_BASE_URL_ENV)
        or DEFAULT_UPSTREAM_BASE_URL
    ).rstrip("/")


def _upstream_url(base_url: str, path: str) -> str:
    """Join an API base URL and request path without duplicating ``/v1``."""
    base_url = base_url.rstrip("/")
    norm_path = "/" + path.lstrip("/")
    if base_url.endswith("/v1") and norm_path.startswith("/v1/"):
        norm_path = norm_path[3:]
    return base_url + norm_path


def _filter_forward_headers(headers: dict[str, str]) -> dict[str, str]:
    """Strip hop-by-hop and secret headers before forwarding to the upstream.

    HTTP headers are case-insensitive; compare on lowercased keys so a
    client sending `Host` / `Content-Length` / `HOST` doesn't slip past
    the filter and confuse the upstream (duplicate Host, mismatched
    content-length, etc.). The `x-dontlie-upstream-key` header is the
    proxy's internal channel for the bearer key and must not be relayed.
    """
    return {
        k: v for k, v in headers.items()
        if k.lower() not in _HOP_BY_HOP_HEADERS
        and k.lower() not in _SECRET_HEADERS
    }


def _make_upstream_client(timeout_s: float = 60.0) -> httpx.AsyncClient:
    """Build a single AsyncClient with sensible connection-pool defaults.

    Limits are intentionally permissive: most users will run a small
    number of concurrent chat-completions and we want headroom for
    streaming and tool-call spikes. Adjust with `httpx.Limits(...)` if
    a deployment needs tighter control.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout_s, connect=10.0),
        limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
    )


def _extract_assistant_text(response_bytes: bytes, was_stream: bool) -> str:
    """Pull assistant text out of either a JSON or SSE response body."""
    if not was_stream:
        try:
            j = json.loads(response_bytes)
            return _text_from_chat_json(j)
        except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
            return response_bytes.decode("utf-8", errors="replace")

    text_parts: list[str] = []
    for raw in response_bytes.split(b"\n"):
        line = raw.decode("utf-8", errors="replace").strip()
        if not line.startswith("data:"):
            continue
        payload = line[len("data:"):].strip()
        if payload in ("", "[DONE]"):
            continue
        try:
            evt = json.loads(payload)
            delta = evt.get("choices", [{}])[0].get("delta", {}).get("content")
            if delta:
                text_parts.append(delta)
        except json.JSONDecodeError:
            continue
    return "".join(text_parts)


def _text_from_chat_json(j: dict[str, Any]) -> str:
    try:
        content = j["choices"][0]["message"]["content"]
        return content if isinstance(content, str) else json.dumps(content)
    except (KeyError, IndexError):
        return json.dumps(j)


def _model_from_body(body: dict[str, Any]) -> str:
    return str(body.get("model", "unknown"))


def _tags_from_body(body: dict[str, Any]) -> list[str]:
    tags: list[str] = []
    if body.get("stream"):
        tags.append("stream")
    if body.get("tools"):
        tags.append("tools")
    return tags


def _response_metadata(
    status: int,
    endpoint: str,
    response_bytes: bytes,
    elapsed_ms: int,
    content_type: str | None = None,
) -> dict[str, Any]:
    """Return signed response metadata, including an optional raw-body copy."""
    metadata: dict[str, Any] = {
        "status": status,
        "endpoint": endpoint,
        "bytes": len(response_bytes),
        "elapsed_ms": elapsed_ms,
        "content_type": content_type,
        "response_sha256": hashlib.sha256(response_bytes).hexdigest(),
    }
    if (
        len(response_bytes) <= MAX_RAW_RESPONSE_BYTES
        and os.environ.get("DONTLIE_STORE_RAW_RESPONSE", "1").lower()
        not in {"0", "false", "no"}
    ):
        metadata["response_raw_b64"] = base64.b64encode(response_bytes).decode("ascii")
    elif len(response_bytes) > MAX_RAW_RESPONSE_BYTES:
        metadata["response_raw_omitted"] = True
    return metadata


async def _stream_response(
    method: str,
    url: str,
    headers: dict[str, str],
    body: dict[str, Any],
    on_chunk: Callable[[bytes], Awaitable[None]],
    on_start: Callable[[int, dict[str, str]], Awaitable[None]] | None = None,
) -> tuple[int, dict[str, str], int]:
    """Forward a streaming request and forward each chunk to ``on_chunk``.

    Returns (status, response_headers, total_bytes). Streams are written
    to the client immediately instead of being buffered, so SSE clients
    see the first token without waiting for the model to finish.
    """
    total = 0
    status = 0
    resp_headers: dict[str, str] = {}
    async with httpx.AsyncClient(
        timeout=httpx.Timeout(60.0, connect=10.0),
    ) as client, client.stream(method, url, headers=headers, json=body) as r:
        status = r.status_code
        resp_headers = dict(r.headers)
        if on_start is not None:
            await on_start(status, resp_headers)
        async for chunk in r.aiter_bytes():
            if not chunk:
                continue
            total += len(chunk)
            await on_chunk(chunk)
    return status, resp_headers, total


async def _forward_and_capture(
    method: str,
    path: str,
    body: dict[str, Any],
    headers: dict[str, str],
    upstream_base_url: str | None = None,
    protocol_adapter: protocols.ProtocolAdapter | None = None,
    auth_config: protocols.AuthConfig | None = None,
) -> tuple[int, dict[str, str], bytes]:
    """Forward request, accumulate streamed body if SSE, return (status, headers, bytes).

    This is the buffered variant used by callers that need the full
    response body in memory (e.g. for receipt extraction). The streaming
    HTTP path uses ``_stream_response`` instead so the client gets
    token-by-token delivery.
    """
    fwd_headers = _filter_forward_headers(headers)
    upstream_key = str(headers.get("x-dontlie-upstream-key", "")).strip()
    if not upstream_key:
        # Fail closed: a missing upstream key would otherwise produce
        # `Authorization: Bearer ` (empty bearer), the upstream would 401,
        # and `handle_chat_completion` would still write a signed receipt
        # for the 401 body — silently signing a non-exchange as if it were
        # a model response. Raise so the caller surfaces a clean error
        # and the operator notices the misconfiguration.
        raise RuntimeError(
            "dontlie proxy: x-dontlie-upstream-key is empty; "
            "DONTLIE_UPSTREAM_API_KEY (or legacy OPENAI_API_KEY) must be set "
            "in the environment that started the proxy."
        )
    if protocol_adapter is None:
        fwd_headers["Authorization"] = f"Bearer {upstream_key}"
    else:
        fwd_headers.update(protocol_adapter.auth_headers(upstream_key, auth_config))
        path = protocol_adapter.request_path(auth_config)

    url = _upstream_url(resolve_upstream_base_url(upstream_base_url), path)
    is_stream = bool(body.get("stream"))

    if is_stream:
        chunks: list[bytes] = []

        async def _collect(chunk: bytes) -> None:
            chunks.append(chunk)

        status, resp_headers, _total_bytes = await _stream_response(
            method, url, fwd_headers, body, _collect,
        )
        _ = _total_bytes  # returned for callers that want the size; not needed here
        return status, resp_headers, b"".join(chunks)

    async with _make_upstream_client() as client:
        r = await client.request(method, url, headers=fwd_headers, json=body)
        return r.status_code, dict(r.headers), r.content


def _validate_chat_body(body: Any) -> tuple[dict[str, Any] | None, str | None]:
    """Best-effort validation of an OpenAI chat-completions body.

    Returns ``(parsed_body, None)`` on success, or ``(None, reason)`` on
    rejection. The upstream itself is the source of truth for content
    rules; we only enforce the shape we depend on for receipt binding
    (``model`` + ``messages``).
    """
    if not isinstance(body, dict):
        return None, "request body must be a JSON object"
    if not isinstance(body.get("model"), str) or not body["model"]:
        return None, "missing or empty 'model' field"
    msgs = body.get("messages")
    if msgs is not None and not isinstance(msgs, list):
        return None, "'messages' must be a list"
    return body, None


def handle_chat_completion(
    body: dict[str, Any],
    upstream_key: str,
    upstream_base_url: str | None = None,
) -> dict[str, Any]:
    """Forward one OpenAI chat completion and append its signed receipt."""
    headers = {"x-dontlie-upstream-key": upstream_key, "content-type": "application/json"}
    t0 = time.monotonic()
    status, resp_headers, resp_bytes = asyncio.run(
        _forward_and_capture(
            "POST",
            "/v1/chat/completions",
            body,
            headers,
            upstream_base_url=upstream_base_url,
        )
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    # Bind the FULL conversation the model actually saw, not just the trailing
    # user turn. A receipt whose hash only covers the last user message could
    # pass verification while the system prompt or earlier turns were silently
    # rewritten by an attacker with DB write access.
    prompt_text = _canonical_messages(body)
    response_text = _extract_assistant_text(resp_bytes, was_stream=bool(body.get("stream")))

    storage.append(
        model=_model_from_body(body),
        prompt=prompt_text,
        response=response_text,
        tags=_tags_from_body(body),
        extra=_response_metadata(
            status,
            "/v1/chat/completions",
            resp_bytes,
            elapsed_ms,
            resp_headers.get("content-type"),
        ),
    )

    content_type = resp_headers.get(
        "content-type",
        "text/event-stream" if body.get("stream") else "application/json",
    )
    if body.get("stream") or not 200 <= status < 300:
        return {
            "_dontlie_passthrough_status": status,
            "_dontlie_passthrough_body": resp_bytes.decode("utf-8", errors="replace"),
            "_dontlie_passthrough_body_bytes": resp_bytes,
            "_dontlie_passthrough_content_type": content_type,
        }
    try:
        parsed = json.loads(resp_bytes)
        return parsed if isinstance(parsed, dict) else {"data": parsed}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {"error": "non-json upstream", "raw": resp_bytes.decode("utf-8", errors="replace")}


def handle_protocol_completion(
    body: dict[str, Any],
    upstream_key: str,
    adapter: protocols.ProtocolAdapter,
    upstream_base_url: str | None = None,
    auth_config: protocols.AuthConfig | None = None,
) -> dict[str, Any]:
    """Forward one provider-native completion and append a signed receipt."""
    parsed, error = adapter.validate_request(body)
    if error is not None or parsed is None:
        raise protocols.ProtocolError(error or "invalid protocol request")
    headers = {
        "x-dontlie-upstream-key": upstream_key,
        "content-type": "application/json",
    }
    endpoint = adapter.request_path(auth_config)
    started = time.monotonic()
    status, response_headers, response_bytes = asyncio.run(
        _forward_and_capture(
            "POST",
            endpoint,
            parsed,
            headers,
            upstream_base_url=upstream_base_url,
            protocol_adapter=adapter,
            auth_config=auth_config,
        )
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    storage.append(
        model=adapter.model(parsed),
        prompt=adapter.canonical_request(parsed),
        response=adapter.response_text(
            response_bytes,
            streamed=adapter.is_stream(parsed) and 200 <= status < 300,
        ),
        tags=adapter.tags(parsed),
        extra=_response_metadata(
            status,
            endpoint,
            response_bytes,
            elapsed_ms,
            response_headers.get("content-type"),
        ),
    )
    content_type = response_headers.get(
        "content-type",
        "text/event-stream" if adapter.is_stream(parsed) else "application/json",
    )
    if adapter.is_stream(parsed) or not 200 <= status < 300:
        return {
            "_dontlie_passthrough_status": status,
            "_dontlie_passthrough_body": response_bytes.decode(
                "utf-8", errors="replace"
            ),
            "_dontlie_passthrough_body_bytes": response_bytes,
            "_dontlie_passthrough_content_type": content_type,
        }
    try:
        decoded = json.loads(response_bytes)
        return decoded if isinstance(decoded, dict) else {"data": decoded}
    except (UnicodeDecodeError, json.JSONDecodeError):
        return {
            "error": "non-json upstream",
            "raw": response_bytes.decode("utf-8", errors="replace"),
        }


def _canonical_messages(body: dict[str, Any]) -> str:
    """Return a stable serialization of the complete upstream request body.

    The historical function name is kept for API compatibility. Signing only
    ``messages`` is insufficient for an audit receipt because model, tools,
    sampling parameters, response format, and token limits can all change the
    answer. Headers and provider credentials are intentionally excluded.
    """
    return json.dumps(
        body,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


# ---------------------------------------------------------------------------
# Streaming HTTP path (used by ``cli.cmd_proxy``)
# ---------------------------------------------------------------------------

async def stream_chat_completion_to_client(
    body: dict[str, Any],
    upstream_key: str,
    write_chunk: Callable[[bytes], Awaitable[None]],
    flush: Callable[[], Awaitable[None]],
    upstream_base_url: str | None = None,
    on_start: Callable[[int, dict[str, str]], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Forward a streaming request to the upstream and write SSE bytes
    straight to the connected client, flushing after each chunk so the
    user sees tokens as they arrive.

    Returns a small dict ``{status, elapsed_ms, bytes}`` for logging.
    The full body is also collected so the receipt can be signed; that
    buffer is what makes "we recorded the *full* assistant text" hold
    even on streaming paths.
    """
    upstream_key = str(upstream_key).strip()
    if not upstream_key:
        raise RuntimeError(
            "dontlie proxy: x-dontlie-upstream-key is empty; "
            "DONTLIE_UPSTREAM_API_KEY (or legacy OPENAI_API_KEY) must be set "
            "in the environment that started the proxy."
        )
    headers = _filter_forward_headers(
        {"x-dontlie-upstream-key": upstream_key, "content-type": "application/json"}
    )
    headers["Authorization"] = f"Bearer {upstream_key}"

    url = _upstream_url(resolve_upstream_base_url(upstream_base_url), "/v1/chat/completions")

    collected: list[bytes] = []

    async def _tee(chunk: bytes) -> None:
        collected.append(chunk)
        await write_chunk(chunk)
        await flush()

    async def _start(status: int, response_headers: dict[str, str]) -> None:
        if on_start is not None:
            await on_start(status, response_headers)

    t0 = time.monotonic()
    status, resp_headers, total = await _stream_response(
        "POST", url, headers, body, _tee, _start,
    )
    elapsed_ms = int((time.monotonic() - t0) * 1000)

    body_bytes = b"".join(collected)
    response_text = _extract_assistant_text(
        body_bytes,
        was_stream=200 <= status < 300,
    )
    storage.append(
        model=_model_from_body(body),
        prompt=_canonical_messages(body),
        response=response_text,
        tags=_tags_from_body(body),
        extra=_response_metadata(
            status,
            "/v1/chat/completions",
            body_bytes,
            elapsed_ms,
            resp_headers.get("content-type"),
        ),
    )
    return {
        "status": status,
        "elapsed_ms": elapsed_ms,
        "bytes": total,
        "content_type": resp_headers.get("content-type"),
    }


async def stream_protocol_to_client(
    body: dict[str, Any],
    upstream_key: str,
    adapter: protocols.ProtocolAdapter,
    write_chunk: Callable[[bytes], Awaitable[None]],
    flush: Callable[[], Awaitable[None]],
    upstream_base_url: str | None = None,
    auth_config: protocols.AuthConfig | None = None,
    on_start: Callable[[int, dict[str, str]], Awaitable[None]] | None = None,
) -> dict[str, Any]:
    """Stream a provider-native response unchanged while signing its text."""
    parsed, error = adapter.validate_request(body)
    if error is not None or parsed is None:
        raise protocols.ProtocolError(error or "invalid protocol request")
    if not adapter.is_stream(parsed):
        raise protocols.ProtocolError("stream_protocol_to_client requires stream=true")
    headers = _filter_forward_headers(
        {
            "x-dontlie-upstream-key": upstream_key,
            "content-type": "application/json",
        }
    )
    headers.update(adapter.auth_headers(upstream_key, auth_config))
    endpoint = adapter.request_path(auth_config)
    url = _upstream_url(resolve_upstream_base_url(upstream_base_url), endpoint)
    collected: list[bytes] = []

    async def _tee(chunk: bytes) -> None:
        collected.append(chunk)
        await write_chunk(chunk)
        await flush()

    started = time.monotonic()
    status, response_headers, total = await _stream_response(
        "POST", url, headers, parsed, _tee, on_start
    )
    elapsed_ms = int((time.monotonic() - started) * 1000)
    response_bytes = b"".join(collected)
    storage.append(
        model=adapter.model(parsed),
        prompt=adapter.canonical_request(parsed),
        response=adapter.response_text(
            response_bytes,
            streamed=200 <= status < 300,
        ),
        tags=adapter.tags(parsed),
        extra=_response_metadata(
            status,
            endpoint,
            response_bytes,
            elapsed_ms,
            response_headers.get("content-type"),
        ),
    )
    return {
        "status": status,
        "elapsed_ms": elapsed_ms,
        "bytes": total,
        "content_type": response_headers.get("content-type"),
        "protocol": adapter.identifier,
    }
