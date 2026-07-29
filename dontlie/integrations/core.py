"""Framework-neutral action events and receipt recording helpers."""

from __future__ import annotations

import contextvars
import functools
import json
import uuid
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Literal, ParamSpec, TypeVar, cast

from dontlie import storage

ActionKind = Literal["model", "tool", "approval", "denial"]
FailureMode = Literal["raise", "return_none"]
P = ParamSpec("P")
R = TypeVar("R")

_CORRELATION_ID: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "dontlie_correlation_id", default=None
)
_SENSITIVE_KEYS = frozenset(
    {
        "api_key",
        "apikey",
        "authorization",
        "cookie",
        "password",
        "private_key",
        "secret",
        "token",
    }
)


class RecordingError(RuntimeError):
    """Raised when an action cannot be converted to a signed receipt."""


@dataclass(frozen=True)
class ActionEvent:
    """Portable event envelope suitable for callbacks and MCP-style transports."""

    action: ActionKind
    name: str
    input: object = None
    output: object = None
    status: str = "completed"
    correlation_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    metadata: Mapping[str, object] = field(default_factory=dict)
    tags: Sequence[str] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, object]:
        return {
            "specversion": "1.0",
            "type": f"dev.dontlie.action.{self.action}",
            "id": uuid.uuid4().hex,
            "source": "dontlie.integrations",
            "time": self.timestamp,
            "subject": self.correlation_id,
            "data": {
                "action": self.action,
                "name": self.name,
                "input": self.input,
                "output": self.output,
                "status": self.status,
                "correlation_id": self.correlation_id,
                "metadata": dict(self.metadata),
                "tags": list(self.tags),
            },
        }

    @classmethod
    def from_dict(cls, envelope: Mapping[str, object]) -> ActionEvent:
        raw_data = envelope.get("data")
        if not isinstance(raw_data, Mapping):
            raise TypeError("event envelope data must be a mapping")
        action = raw_data.get("action")
        if action not in {"model", "tool", "approval", "denial"}:
            raise ValueError("event action must be model, tool, approval, or denial")
        name = raw_data.get("name")
        if not isinstance(name, str) or not name:
            raise TypeError("event name must be a non-empty string")
        correlation_id = raw_data.get("correlation_id", envelope.get("subject"))
        if not isinstance(correlation_id, str) or not correlation_id:
            raise TypeError("event correlation_id must be a non-empty string")
        status = raw_data.get("status", "completed")
        if not isinstance(status, str):
            raise TypeError("event status must be a string")
        metadata = raw_data.get("metadata", {})
        if not isinstance(metadata, Mapping):
            raise TypeError("event metadata must be a mapping")
        tags = raw_data.get("tags", ())
        if not isinstance(tags, Sequence) or isinstance(tags, (str, bytes)):
            raise TypeError("event tags must be a sequence")
        event_time = envelope.get("time")
        return cls(
            action=cast(ActionKind, action),
            name=name,
            input=raw_data.get("input"),
            output=raw_data.get("output"),
            status=status,
            correlation_id=correlation_id,
            timestamp=(
                event_time
                if isinstance(event_time, str)
                else datetime.now(timezone.utc).isoformat()
            ),
            metadata=dict(metadata),
            tags=tuple(str(tag) for tag in tags),
        )


def _sanitize(value: object) -> object:
    if isinstance(value, Mapping):
        return {
            str(key): (
                "[REDACTED]"
                if str(key).lower() in _SENSITIVE_KEYS
                else _sanitize(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [_sanitize(item) for item in value]
    return value


def _serialize(value: object) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    except (TypeError, ValueError) as exc:
        raise RecordingError("action payload is not serializable") from exc


def current_correlation_id() -> str:
    return _CORRELATION_ID.get() or uuid.uuid4().hex


@contextmanager
def correlation_scope(correlation_id: str | None = None) -> Iterator[str]:
    value = correlation_id or uuid.uuid4().hex
    token = _CORRELATION_ID.set(value)
    try:
        yield value
    finally:
        _CORRELATION_ID.reset(token)


class ActionRecorder:
    """Record portable action events using the existing signed receipt shape."""

    def __init__(
        self, *, failure_mode: FailureMode = "raise", redact: bool = True
    ) -> None:
        if failure_mode not in {"raise", "return_none"}:
            raise ValueError("failure_mode must be raise or return_none")
        self.failure_mode = failure_mode
        self.redact = redact

    def record(self, event: ActionEvent) -> storage.Receipt | None:
        payload_input = _sanitize(event.input) if self.redact else event.input
        payload_output = _sanitize(event.output) if self.redact else event.output
        extra: dict[str, object] = {
            "integration": {
                "action": event.action,
                "name": event.name,
                "status": event.status,
                "correlation_id": event.correlation_id,
                "event_timestamp": event.timestamp,
                "metadata": (
                    _sanitize(dict(event.metadata))
                    if self.redact
                    else dict(event.metadata)
                ),
            }
        }
        try:
            return storage.append(
                model=event.name,
                prompt=_serialize(payload_input),
                response=_serialize(payload_output),
                tags=["integration", event.action, *event.tags],
                extra=extra,
            )
        except Exception as exc:
            if self.failure_mode == "return_none":
                return None
            if isinstance(exc, RecordingError):
                raise
            raise RecordingError(f"failed to record {event.action} action") from exc

    def callback(self, envelope: Mapping[str, object]) -> storage.Receipt | None:
        try:
            return self.record(ActionEvent.from_dict(envelope))
        except Exception as exc:
            if self.failure_mode == "return_none":
                return None
            if isinstance(exc, (RecordingError, ValueError, TypeError)):
                raise
            raise RecordingError("failed to process action event") from exc

    @contextmanager
    def action(
        self,
        action: ActionKind,
        name: str,
        input: object = None,
        *,
        correlation_id: str | None = None,
        metadata: Mapping[str, object] | None = None,
        tags: Sequence[str] = (),
    ) -> Iterator[dict[str, object]]:
        state: dict[str, object] = {"output": None}
        cid = correlation_id or current_correlation_id()
        try:
            yield state
        except Exception as exc:
            state["output"] = {"error_type": type(exc).__name__}
            self.record(
                ActionEvent(
                    action=action,
                    name=name,
                    input=input,
                    output=state["output"],
                    status="failed",
                    correlation_id=cid,
                    metadata=metadata or {},
                    tags=tags,
                )
            )
            raise
        else:
            self.record(
                ActionEvent(
                    action=action,
                    name=name,
                    input=input,
                    output=state.get("output"),
                    correlation_id=cid,
                    metadata=metadata or {},
                    tags=tags,
                )
            )

    def decorate(
        self,
        action: ActionKind,
        name: str | None = None,
        *,
        metadata: Mapping[str, object] | None = None,
        tags: Sequence[str] = (),
    ) -> Callable[[Callable[P, R]], Callable[P, R]]:
        def decorator(func: Callable[P, R]) -> Callable[P, R]:
            @functools.wraps(func)
            def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
                event_name = name or func.__qualname__
                cid = current_correlation_id()
                try:
                    result = func(*args, **kwargs)
                except Exception as exc:
                    self.record(
                        ActionEvent(
                            action=action,
                            name=event_name,
                            input={"args": args, "kwargs": kwargs},
                            output={"error_type": type(exc).__name__},
                            status="failed",
                            correlation_id=cid,
                            metadata=metadata or {},
                            tags=tags,
                        )
                    )
                    raise
                self.record(
                    ActionEvent(
                        action=action,
                        name=event_name,
                        input={"args": args, "kwargs": kwargs},
                        output=result,
                        correlation_id=cid,
                        metadata=metadata or {},
                        tags=tags,
                    )
                )
                return result

            return wrapped

        return decorator


def record_action(
    action: ActionKind,
    name: str,
    input: object = None,
    output: object = None,
    *,
    status: str = "completed",
    correlation_id: str | None = None,
    metadata: Mapping[str, object] | None = None,
    tags: Sequence[str] = (),
    failure_mode: FailureMode = "raise",
) -> storage.Receipt | None:
    return ActionRecorder(failure_mode=failure_mode).record(
        ActionEvent(
            action=action,
            name=name,
            input=input,
            output=output,
            status=status,
            correlation_id=correlation_id or current_correlation_id(),
            metadata=metadata or {},
            tags=tags,
        )
    )
