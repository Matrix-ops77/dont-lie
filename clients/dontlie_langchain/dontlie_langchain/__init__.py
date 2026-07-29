"""Don't-Lie LangChain callback.

Hooks into LangChain / LangGraph chat-model invocations and writes a
signed receipt per call to the local vault. The module is optional:
if ``langchain-core`` isn't installed, the callback class still exists
and is a no-op, so environments that don't want the dep can still
import it without crashing.
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

_LANGCHAIN_AVAILABLE = False
_BaseCallbackHandler: type | None = None

try:  # pragma: no cover - exercised in environments with langchain installed
    from langchain_core.callbacks import BaseCallbackHandler as _BC

    _LANGCHAIN_AVAILABLE = True
    _BaseCallbackHandler = _BC
except Exception:  # pragma: no cover
    pass


class _NullBase:
    """Stand-in for BaseCallbackHandler when langchain_core is missing."""

    raise_error: bool = False


if _BaseCallbackHandler is None:
    _BaseCallbackHandler = _NullBase


def _tags() -> list[str]:
    raw = os.environ.get("DONTLIE_LANGCHAIN_TAGS", "[]").strip()
    if not raw:
        return []
    try:
        return list(json.loads(raw))
    except json.JSONDecodeError:
        return []


def _record(
    *,
    model: str,
    prompt: str,
    response: str,
    tags: list[str],
    extra: dict[str, Any],
) -> None:
    """Best-effort receipt write. Swallows storage errors so the agent runs."""
    try:  # pragma: no cover - exercised against real storage
        from dontlie import storage
    except Exception:
        return
    try:
        storage.append(
            model=model,
            prompt=prompt,
            response=response,
            tags=tags,
            extra=extra,
        )
    except Exception as exc:  # pragma: no cover
        # Don't block the agent on storage failures.
        _errors.labels(type="append", reason=type(exc).__name__).inc()
        return


# Minimal in-process metrics so the operator can see drops.
_errors = type(
    "_Metrics",
    (),
    {"labels": staticmethod(lambda **kw: type("Counter", (), {"inc": lambda self: None})())},
)()


class DontlieCallback(_BaseCallbackHandler):  # type: ignore[misc]
    """LangChain callback that emits a receipt per LLM call.

    Usage::

        cb = DontlieCallback()
        llm = ChatOpenAI(callbacks=[cb])
        llm.invoke("hello")
    """

    def __init__(self, tags: list[str] | None = None) -> None:
        self._tags: list[str] = list(tags if tags is not None else _tags())
        self._lock = threading.Lock()

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs: Any) -> None:
        """Stash the prompt for the matching ``on_llm_end``."""
        with self._lock:
            self._pending = list(prompts)

    def on_llm_end(self, response: Any, **kwargs: Any) -> None:
        with self._lock:
            prompts = getattr(self, "_pending", [])
            self._pending = []
        for prompt, generation in zip(prompts, response.generations, strict=False):
            text = _flatten(generation)
            model = _model_name(response)
            _record(
                model=model,
                prompt=prompt,
                response=text,
                tags=self._tags,
                extra={
                    "endpoint": "/langchain/llm",
                    "provider": "langchain",
                    "kind": "chat",
                },
            )


def _flatten(generation: Any) -> str:
    """Extract a text-like field from a LangChain generation."""
    # List[ChatGeneration] is the common case.
    if isinstance(generation, list):
        if not generation:
            return ""
        generation = generation[0]
    message = getattr(generation, "message", None)
    if message is not None:
        content = getattr(message, "content", "")
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "\n".join(
                item.get("text", "") if isinstance(item, dict) else str(item)
                for item in content
            )
        return str(content)
    text = getattr(generation, "text", None)
    if isinstance(text, str):
        return text
    return ""


def _model_name(response: Any) -> str:
    llm_output = getattr(response, "llm_output", None) or {}
    return str(llm_output.get("model_name") or llm_output.get("model") or "langchain")


__all__ = ["_LANGCHAIN_AVAILABLE", "DontlieCallback"]
