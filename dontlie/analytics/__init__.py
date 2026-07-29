"""PostHog / Plausible / Mixpanel compatible analytics for Don't-Lie.

Captures activation events when the host product wires it in. We don't
phone home — events are queued locally and either dropped (local mode)
or POSTed to the configured endpoint.

Activation events this product cares about:

- ``receipt.captured``  — every signed receipt
- ``receipt.verified``  — every successful chain verification
- ``receipt.tampered``  — any receipt that fails verification
- ``receipt.exported``  — portable bundle generation
- ``vault.encrypted``   — operator vault unlocked
- ``checkout.started``  — buyer initiates checkout
- ``checkout.completed``— buyer completes checkout
- ``upgrade.tier``      — buyer moves up a tier
- ``demo.ran``          — local demo ran to completion
- ``key.revoked``       — signing key marked revoked

The module is dependency-light: the HTTP sink uses ``urllib`` from the
stdlib. The in-memory sink is exposed for tests.

Set ``DONTLIE_ANALYTICS_OFF=1`` to disable all emission.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Iterable


class AnalyticsError(RuntimeError):
    """Raised when an analytics sink cannot accept an event."""


@dataclass(frozen=True)
class Event:
    name: str
    properties: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=lambda: time.time())

    def to_dict(self) -> dict[str, Any]:
        return {"event": self.name, "properties": dict(self.properties), "timestamp": self.timestamp}


class InMemorySink:
    """Collects events in a list. Useful for tests and local debugging."""

    def __init__(self) -> None:
        self.events: list[Event] = []

    def emit(self, event: Event) -> None:
        self.events.append(event)

    def names(self) -> list[str]:
        return [event.name for event in self.events]


class HttpSink:
    """POSTs events to a configured endpoint as JSON.

    The endpoint should accept a JSON body of the form
    ``{"event": "...", "properties": {...}, "timestamp": ...}``.
    Compatible with PostHog's capture endpoint when paired with a
    transformation proxy.
    """

    def __init__(self, url: str, headers: dict[str, str] | None = None) -> None:
        self.url = url
        self.headers = dict(headers or {"Content-Type": "application/json"})

    def emit(self, event: Event) -> None:
        body = json.dumps(event.to_dict()).encode("utf-8")
        req = urllib.request.Request(self.url, data=body, headers=self.headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=10):
                return
        except urllib.error.URLError as exc:
            raise AnalyticsError(f"{self.url} -> {exc.reason}") from exc


class Analytics:
    """Fan-out sink with a single in-memory buffer."""

    def __init__(self, sinks: Iterable[object] | None = None) -> None:
        self.sinks: list[object] = list(sinks or [])
        if not self.sinks and not os.environ.get("DONTLIE_ANALYTICS_OFF"):
            self.sinks.append(InMemorySink())

    def emit(self, name: str, **properties: Any) -> None:
        if os.environ.get("DONTLIE_ANALYTICS_OFF"):
            return
        event = Event(name=name, properties=dict(properties))
        for sink in self.sinks:
            try:
                sink.emit(event)  # type: ignore[attr-defined]
            except AnalyticsError:
                # Never let analytics fail the host operation.
                continue


def capture_receipt(receipt_id: int, model: str) -> None:
    Analytics().emit("receipt.captured", id=receipt_id, model=model)


def capture_verified(receipt_id: int, ok: bool) -> None:
    Analytics().emit("receipt.verified", id=receipt_id, ok=ok)


def capture_tampered(receipt_id: int, reason: str) -> None:
    Analytics().emit("receipt.tampered", id=receipt_id, reason=reason)


def capture_export(path: str, count: int) -> None:
    Analytics().emit("receipt.exported", path=path, count=count)


def capture_checkout_started(tier: str, email: str) -> None:
    Analytics().emit("checkout.started", tier=tier, email=email)


def capture_checkout_completed(tier: str, amount_cents: int) -> None:
    Analytics().emit("checkout.completed", tier=tier, amount_cents=amount_cents)


def capture_demo_run(receipts: int) -> None:
    Analytics().emit("demo.ran", receipts=receipts)


__all__ = [
    "Analytics",
    "AnalyticsError",
    "Event",
    "HttpSink",
    "InMemorySink",
    "capture_checkout_completed",
    "capture_checkout_started",
    "capture_demo_run",
    "capture_export",
    "capture_receipt",
    "capture_tampered",
    "capture_verified",
]
