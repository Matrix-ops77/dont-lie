"""Dependency-light action recording for AI and tool integrations."""

from .core import (
    ActionEvent,
    ActionRecorder,
    RecordingError,
    correlation_scope,
    record_action,
)

__all__ = [
    "ActionEvent",
    "ActionRecorder",
    "RecordingError",
    "correlation_scope",
    "record_action",
]
