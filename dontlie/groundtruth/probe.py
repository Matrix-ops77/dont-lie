"""Blind-probe API for the ground-truth lane.

A ``BlindProbe`` is the operator-side way to confirm the same response
came from the same provider the receipt claims. The default mode is
``offline`` and rejects any ``run`` call; the operator must call
``attach_runner`` (or supply a custom factory) to make the probe
actually contact an upstream.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


class BlindProbeUnavailable(RuntimeError):
    """Raised when no runner is attached and no network fallback is wired."""


@dataclass
class BlindProbeResult:
    provider: str
    model: str
    response_sha256: str
    response_digest: str
    elapsed_ms: int
    correlation_id: str

    def canonical(self) -> dict[str, Any]:
        return asdict(self)


_RUNNER: Any | None = None


def attach_runner(runner: Any) -> None:
    """Inject a runner that the blind probe will dispatch to.

    The runner may be either a callable ``prompt -> BlindProbeResult`` or
    an object exposing a ``run(prompt)`` method (duck-typed). Both
    shapes are supported so callers can subclass or compose without
    ceremony.
    """
    global _RUNNER
    _RUNNER = runner


def reset_runner() -> None:
    """Drop any attached runner."""
    global _RUNNER
    _RUNNER = None


class BlindProbe:
    """Send a blinded probe to the configured upstream provider.

    The default mode is ``offline`` and rejects any ``run`` call; callers
    must ``attach_runner`` (or supply a custom factory) to make the
    probe actually contact an upstream.
    """

    MODES = ("offline", "runner")

    def __init__(self, mode: str = "offline") -> None:
        if mode not in self.MODES:
            raise ValueError(f"unsupported mode: {mode!r}")
        self.mode = mode

    def run(self, prompt: str) -> BlindProbeResult:
        if _RUNNER is None:
            raise BlindProbeUnavailable(
                "no runner attached; call attach_runner() first"
            )
        if callable(_RUNNER):
            return _RUNNER(prompt)
        run = getattr(_RUNNER, "run", None)
        if run is None:
            raise BlindProbeUnavailable(
                "attached runner exposes neither __call__ nor .run"
            )
        return run(prompt)


__all__ = ["BlindProbe", "BlindProbeResult", "BlindProbeUnavailable", "attach_runner", "reset_runner"]
