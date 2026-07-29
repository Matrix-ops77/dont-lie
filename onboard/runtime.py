"""Fail-open, import-time instrumentation for major Python model SDKs.

This module intentionally imports no provider SDK. A small meta-path hook waits
for supported SDK modules, then wraps their final request methods. All capture,
serialization, key, and storage failures are swallowed so instrumentation can
never change the provider call's success/failure behavior.
"""

from __future__ import annotations

import functools
import hashlib
import importlib.abc
import importlib.machinery
import inspect
import json
import os
import sys
import threading
from collections.abc import AsyncIterator, Iterable, Iterator, Mapping, Sequence
from dataclasses import asdict, is_dataclass
from pathlib import Path
from types import ModuleType
from typing import ClassVar, cast

OPENAI_PROVIDER = "openai"
ANTHROPIC_PROVIDER = "anthropic"
GEMINI_PROVIDER = "gemini"

_DISABLE_VALUES = {"0", "false", "no", "off", "disabled"}
_PROJECT_MARKERS = (".git", "pyproject.toml", "package.json", "setup.py")
_SECRET_NAMES = {
    "api_key",
    "apikey",
    "authorization",
    "auth_token",
    "access_token",
    "secret",
    "token",
    "x-api-key",
}
_TRANSPORT_NAMES = {"headers", "extra_headers", "http_headers"}
_MAX_DEPTH = 12
_MAX_REPR = 8_192
_RECORD_LOCK = threading.RLock()
_LOCAL = threading.local()


def discover_vault(
    cwd: Path | None = None,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve a per-project vault from env, an existing vault, or project root."""
    environment = os.environ if environ is None else environ
    working_dir = (cwd or Path.cwd()).resolve()
    project_vault = environment.get("DONTLIE_PROJECT_VAULT")
    legacy_db = environment.get("DONTLIE_DB")
    explicit = project_vault or legacy_db
    if explicit:
        candidate = Path(explicit).expanduser()
        if not candidate.is_absolute():
            candidate = working_dir / candidate
        if project_vault and candidate.suffix.lower() not in {
            ".db",
            ".sqlite",
            ".sqlite3",
        }:
            candidate = candidate / "vault.db"
        return candidate.resolve()

    parents = (working_dir, *working_dir.parents)
    for parent in parents:
        existing = parent / ".dontlie" / "vault.db"
        if existing.exists():
            return existing
    for parent in parents:
        if any((parent / marker).exists() for marker in _PROJECT_MARKERS):
            return parent / ".dontlie" / "vault.db"
    return working_dir / ".dontlie" / "vault.db"


def passive_enabled(environ: Mapping[str, str] | None = None) -> bool:
    environment = os.environ if environ is None else environ
    return (
        environment.get("DONTLIE_PASSIVE", "1").strip().lower() not in _DISABLE_VALUES
    )


def _safe_json(value: object) -> str:
    normalized = _normalize(value, seen=set(), depth=0)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


def _normalize(value: object, *, seen: set[int], depth: int) -> object:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, bytes):
        return {
            "_type": "bytes",
            "length": len(value),
            "sha256": hashlib.sha256(value).hexdigest(),
        }
    if depth >= _MAX_DEPTH:
        return {"_truncated": "maximum serialization depth reached"}

    identity = id(value)
    if identity in seen:
        return {"_cycle": type(value).__name__}
    seen.add(identity)
    try:
        if isinstance(value, Mapping):
            result: dict[str, object] = {}
            for raw_key, item in value.items():
                key = str(raw_key)
                lowered = key.lower().replace("-", "_")
                if lowered in {name.replace("-", "_") for name in _SECRET_NAMES}:
                    result[key] = "[redacted credential]"
                elif lowered in _TRANSPORT_NAMES:
                    result[key] = "[omitted transport metadata]"
                else:
                    result[key] = _normalize(item, seen=seen, depth=depth + 1)
            return result
        if isinstance(value, (list, tuple, set, frozenset)):
            return [_normalize(item, seen=seen, depth=depth + 1) for item in value]
        if is_dataclass(value) and not isinstance(value, type):
            return _normalize(asdict(value), seen=seen, depth=depth + 1)
        for method_name in ("model_dump", "to_dict", "dict"):
            method = getattr(value, method_name, None)
            if callable(method):
                try:
                    converted = (
                        method(mode="json") if method_name == "model_dump" else method()
                    )
                except (TypeError, ValueError, RuntimeError):
                    continue
                return _normalize(converted, seen=seen, depth=depth + 1)
        text = repr(value)
        if len(text) > _MAX_REPR:
            text = text[:_MAX_REPR] + "…"
        return {"_type": type(value).__name__, "_repr": text}
    finally:
        seen.discard(identity)


def _capture_request(
    provider: str,
    method: str,
    args: tuple[object, ...],
    kwargs: Mapping[str, object],
) -> tuple[str, str]:
    model = kwargs.get("model")
    if model is None and args and isinstance(args[0], str):
        model = args[0]
    request = {
        "capture_version": 1,
        "provider": provider,
        "method": method,
        "args": args,
        "kwargs": kwargs,
    }
    return str(model or "unknown"), _safe_json(request)


def _exception_payload(error: BaseException) -> dict[str, object]:
    message = str(error)
    if len(message) > _MAX_REPR:
        message = message[:_MAX_REPR] + "…"
    return {
        "error_type": type(error).__name__,
        "message": message,
    }


def _append_receipt(
    *,
    provider: str,
    method: str,
    model: str,
    prompt: str,
    response: object,
    outcome: str,
    streamed: bool,
) -> None:
    """Append via the existing signed chain, restoring its global DB path."""
    if getattr(_LOCAL, "recording", False):
        return
    _LOCAL.recording = True
    try:
        from dontlie import sign as signing
        from dontlie import storage

        vault = discover_vault()
        with _RECORD_LOCK:
            old_path = storage.DB_PATH
            try:
                storage.DB_PATH = vault
                try:
                    signing.load()
                except (FileNotFoundError, OSError, ValueError, json.JSONDecodeError):
                    signing.generate()
                storage.append(
                    model=model,
                    prompt=prompt,
                    response=_safe_json(response),
                    tags=[
                        "passive",
                        f"provider:{provider}",
                        *(["stream"] if streamed else []),
                    ],
                    extra={
                        "passive_capture_version": 1,
                        "provider": provider,
                        "method": method,
                        "outcome": outcome,
                        "streamed": streamed,
                        "vault_discovery": "env-or-project-cwd",
                    },
                )
            finally:
                storage.DB_PATH = old_path
    except Exception:  # noqa: BLE001
        # This is the core contract: observability is never on the user's
        # provider-call failure path.
        return
    finally:
        _LOCAL.recording = False


class _Capture:
    def __init__(
        self,
        provider: str,
        method: str,
        args: tuple[object, ...],
        kwargs: Mapping[str, object],
        instance: object | None = None,
    ) -> None:
        self.provider = provider
        self.method = method
        capture_kwargs = dict(kwargs)
        if "model" not in capture_kwargs and instance is not None:
            for attribute in ("model_name", "model", "_model"):
                try:
                    candidate = getattr(instance, attribute, None)
                except Exception:  # noqa: BLE001,S112
                    continue
                if isinstance(candidate, str) and candidate:
                    capture_kwargs["model"] = candidate
                    break
        try:
            self.model, self.prompt = _capture_request(
                provider,
                method,
                args,
                capture_kwargs,
            )
        except Exception:  # noqa: BLE001
            self.model = str(capture_kwargs.get("model", "unknown"))
            self.prompt = json.dumps(
                {
                    "capture_version": 1,
                    "provider": provider,
                    "method": method,
                    "capture_error": "request serialization failed",
                },
                sort_keys=True,
                separators=(",", ":"),
            )

    def success(self, response: object, *, streamed: bool = False) -> None:
        try:
            _append_receipt(
                provider=self.provider,
                method=self.method,
                model=self.model,
                prompt=self.prompt,
                response=response,
                outcome="success",
                streamed=streamed,
            )
        except Exception:  # noqa: BLE001
            return

    def failure(self, error: BaseException, *, streamed: bool = False) -> None:
        try:
            _append_receipt(
                provider=self.provider,
                method=self.method,
                model=self.model,
                prompt=self.prompt,
                response=_exception_payload(error),
                outcome="error",
                streamed=streamed,
            )
        except Exception:  # noqa: BLE001
            return


class _SyncStreamProxy:
    """Transparent-enough stream proxy that signs consumed chunks on close."""

    def __init__(self, stream: object, capture: _Capture) -> None:
        self._stream = stream
        self._active_stream = stream
        self._iterator: Iterator[object] | None = None
        self._capture = capture
        self._chunks: list[object] = []
        self._finished = False

    def __iter__(self) -> _SyncStreamProxy:
        if self._iterator is None:
            self._iterator = iter(cast(Iterable[object], self._active_stream))
        return self

    def __next__(self) -> object:
        if self._iterator is None:
            self._iterator = iter(cast(Iterable[object], self._active_stream))
        try:
            chunk = next(self._iterator)
        except StopIteration:
            self._finish("success")
            raise
        except BaseException as error:
            self._finish("error", error)
            raise
        self._chunks.append(chunk)
        return chunk

    def __enter__(self) -> _SyncStreamProxy:  # noqa: PYI034
        enter = getattr(self._stream, "__enter__", None)
        if callable(enter):
            entered = enter()
            if entered is not None:
                self._active_stream = entered
        return self

    def __exit__(
        self, exc_type: object, exc: BaseException | None, tb: object
    ) -> object:
        if exc is None:
            self._finish("success")
        else:
            self._finish("error", exc)
        exit_method = getattr(self._stream, "__exit__", None)
        if callable(exit_method):
            return exit_method(exc_type, exc, tb)
        return False

    def close(self) -> None:
        try:
            close = getattr(self._stream, "close", None)
            if callable(close):
                close()
        finally:
            self._finish("success")

    def _finish(
        self,
        outcome: str,
        error: BaseException | None = None,
    ) -> None:
        if self._finished:
            return
        self._finished = True
        if error is None:
            self._capture.success(self._chunks, streamed=True)
        else:
            self._capture.failure(error, streamed=True)

    def __getattr__(self, name: str) -> object:
        return getattr(self._active_stream, name)


class _AsyncStreamProxy:
    def __init__(self, stream: object, capture: _Capture) -> None:
        self._stream = stream
        self._active_stream = stream
        self._iterator: AsyncIterator[object] | None = None
        self._capture = capture
        self._chunks: list[object] = []
        self._finished = False

    def __aiter__(self) -> _AsyncStreamProxy:
        if self._iterator is None:
            self._iterator = self._active_stream.__aiter__()  # type: ignore[attr-defined]
        return self

    async def __anext__(self) -> object:
        if self._iterator is None:
            self._iterator = self._active_stream.__aiter__()  # type: ignore[attr-defined]
        try:
            chunk = await self._iterator.__anext__()
        except StopAsyncIteration:
            self._finish("success")
            raise
        except BaseException as error:
            self._finish("error", error)
            raise
        self._chunks.append(chunk)
        return chunk

    async def __aenter__(self) -> _AsyncStreamProxy:  # noqa: PYI034
        enter = getattr(self._stream, "__aenter__", None)
        if callable(enter):
            entered = await enter()
            if entered is not None:
                self._active_stream = entered
        return self

    async def __aexit__(
        self,
        exc_type: object,
        exc: BaseException | None,
        tb: object,
    ) -> object:
        if exc is None:
            self._finish("success")
        else:
            self._finish("error", exc)
        exit_method = getattr(self._stream, "__aexit__", None)
        if callable(exit_method):
            return await exit_method(exc_type, exc, tb)
        return False

    async def aclose(self) -> None:
        try:
            close = getattr(self._stream, "aclose", None)
            if callable(close):
                await close()
        finally:
            self._finish("success")

    def _finish(
        self,
        outcome: str,
        error: BaseException | None = None,
    ) -> None:
        if self._finished:
            return
        self._finished = True
        if error is None:
            self._capture.success(self._chunks, streamed=True)
        else:
            self._capture.failure(error, streamed=True)

    def __getattr__(self, name: str) -> object:
        return getattr(self._active_stream, name)


def _stream_requested(method_name: str, kwargs: Mapping[str, object]) -> bool:
    return (
        method_name == "stream"
        or method_name.endswith("_stream")
        or kwargs.get("stream") is True
    )


def _wrap_method(
    owner: type,
    method_name: str,
    provider: str,
) -> bool:
    original = getattr(owner, method_name, None)
    if not callable(original) or getattr(original, "__dontlie_passive__", False):
        return False

    qualified = f"{owner.__module__}.{owner.__name__}.{method_name}"
    if inspect.iscoroutinefunction(original):

        @functools.wraps(original)
        async def async_wrapper(
            instance: object,
            *args: object,
            **kwargs: object,
        ) -> object:
            capture = _Capture(provider, qualified, args, kwargs, instance)
            try:
                result = await original(instance, *args, **kwargs)
            except BaseException as error:
                capture.failure(error)
                raise
            if _stream_requested(method_name, kwargs) and (
                hasattr(result, "__aiter__") or hasattr(result, "__aenter__")
            ):
                return _AsyncStreamProxy(result, capture)
            if _stream_requested(method_name, kwargs) and (
                hasattr(result, "__iter__") or hasattr(result, "__enter__")
            ):
                return _SyncStreamProxy(result, capture)
            capture.success(result)
            return result

        async_wrapper.__dontlie_passive__ = True  # type: ignore[attr-defined]
        setattr(owner, method_name, async_wrapper)
        return True

    @functools.wraps(original)
    def sync_wrapper(
        instance: object,
        *args: object,
        **kwargs: object,
    ) -> object:
        capture = _Capture(provider, qualified, args, kwargs, instance)
        try:
            result = original(instance, *args, **kwargs)
        except BaseException as error:
            capture.failure(error)
            raise
        if _stream_requested(method_name, kwargs) and (
            hasattr(result, "__aiter__") or hasattr(result, "__aenter__")
        ):
            return _AsyncStreamProxy(result, capture)
        if _stream_requested(method_name, kwargs) and (
            hasattr(result, "__iter__") or hasattr(result, "__enter__")
        ):
            return _SyncStreamProxy(result, capture)
        capture.success(result)
        return result

    sync_wrapper.__dontlie_passive__ = True  # type: ignore[attr-defined]
    setattr(owner, method_name, sync_wrapper)
    return True


class SDKPatcher:
    """Idempotently patch supported classes without importing provider SDKs."""

    _TARGETS: ClassVar[dict[str, tuple[tuple[str, tuple[str, ...]], ...]]] = {
        OPENAI_PROVIDER: (
            ("Completions", ("create", "stream")),
            ("AsyncCompletions", ("create", "stream")),
        ),
        ANTHROPIC_PROVIDER: (
            ("Messages", ("create", "stream")),
            ("AsyncMessages", ("create", "stream")),
        ),
        GEMINI_PROVIDER: (
            (
                "GenerativeModel",
                ("generate_content", "generate_content_async"),
            ),
            ("Models", ("generate_content", "generate_content_stream")),
            ("AsyncModels", ("generate_content", "generate_content_stream")),
        ),
    }

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self.patched_methods: set[str] = set()

    def patch_loaded_modules(self) -> None:
        with self._lock:
            for name, module in tuple(sys.modules.items()):
                if module is None:
                    continue
                provider = self._provider_for_module(name)
                if provider is None:
                    continue
                self._patch_module(module, provider)

    @staticmethod
    def _provider_for_module(module_name: str) -> str | None:
        if module_name == "openai" or module_name.startswith("openai."):
            return OPENAI_PROVIDER
        if module_name == "anthropic" or module_name.startswith("anthropic."):
            return ANTHROPIC_PROVIDER
        if module_name in {
            "google.generativeai",
            "google.genai",
        } or module_name.startswith(("google.generativeai.", "google.genai.")):
            return GEMINI_PROVIDER
        return None

    def _patch_module(self, module: ModuleType, provider: str) -> None:
        for class_name, method_names in self._TARGETS[provider]:
            owner = getattr(module, class_name, None)
            if not isinstance(owner, type):
                continue
            for method_name in method_names:
                if _wrap_method(owner, method_name, provider):
                    self.patched_methods.add(
                        f"{owner.__module__}.{owner.__name__}.{method_name}"
                    )


class _PatchLoader(importlib.abc.Loader):
    def __init__(self, delegate: importlib.abc.Loader, patcher: SDKPatcher) -> None:
        self._delegate = delegate
        self._patcher = patcher

    def create_module(self, spec: object) -> ModuleType | None:
        create = getattr(self._delegate, "create_module", None)
        return create(spec) if callable(create) else None

    def exec_module(self, module: ModuleType) -> None:
        self._delegate.exec_module(module)
        try:
            self._patcher.patch_loaded_modules()
        except Exception:  # noqa: BLE001
            return

    def __getattr__(self, name: str) -> object:
        return getattr(self._delegate, name)


class _PatchFinder(importlib.abc.MetaPathFinder):
    _dontlie_passive_finder = True

    def __init__(self, patcher: SDKPatcher) -> None:
        self._patcher = patcher

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None = None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        if SDKPatcher._provider_for_module(fullname) is None:
            return None
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if (
            spec is None
            or spec.loader is None
            or not hasattr(spec.loader, "exec_module")
            or isinstance(spec.loader, _PatchLoader)
        ):
            return spec
        spec.loader = _PatchLoader(spec.loader, self._patcher)
        return spec


_PATCHER = SDKPatcher()


def install() -> SDKPatcher:
    """Install the passive import hook; safe and idempotent at process start."""
    if not passive_enabled():
        os.environ.pop("DONTLIE_PASSIVE_ACTIVE", None)
        return _PATCHER
    try:
        _PATCHER.patch_loaded_modules()
        if not any(
            getattr(finder, "_dontlie_passive_finder", False)
            for finder in sys.meta_path
        ):
            sys.meta_path.insert(0, _PatchFinder(_PATCHER))
        os.environ["DONTLIE_PASSIVE_ACTIVE"] = "1"
    except Exception:  # noqa: BLE001
        # sitecustomize must never make a Python process fail to start.
        return _PATCHER
    return _PATCHER
