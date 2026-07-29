"""Operator alerting via generic webhooks.

This module pushes Don't-Lie events (chain break, key revoked, etc.) to
generic webhook endpoints such as Slack, Microsoft Teams, Discord, or a
custom HTTP listener. The cloud-specific signature formats are not
implemented here — for those, wrap ``send_event`` with a thin adapter
that handles the platform's challenge/secret handshake.

This module is dependency-light: it uses only ``urllib`` from the
standard library. It is intentionally synchronous; production users
should run it inside a background queue.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request
from collections.abc import Iterable
from dataclasses import dataclass, field


class AlertError(RuntimeError):
    """Raised when an alert cannot be delivered."""


@dataclass(frozen=True)
class Alert:
    title: str
    body: str
    severity: str = "info"  # info | warning | critical
    tags: tuple[str, ...] = ()

    def to_payload(self) -> dict:
        return {
            "title": self.title,
            "body": self.body,
            "severity": self.severity,
            "tags": list(self.tags),
            "timestamp": int(time.time()),
        }


@dataclass
class AlertSink:
    name: str
    url: str
    secret: str | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def sign(self, body: bytes) -> dict[str, str]:
        extra = dict(self.headers)
        if self.secret:
            digest = hmac.new(
                self.secret.encode("utf-8"), body, hashlib.sha256
            ).hexdigest()
            extra["X-Dontlie-Signature"] = f"sha256={digest}"
        return extra


def _post(url: str, body: bytes, headers: dict[str, str]) -> int:
    req = urllib.request.Request(
        url,
        data=body,
        headers={"Content-Type": "application/json", **headers},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status
    except urllib.error.HTTPError as exc:  # pragma: no cover
        raise AlertError(f"POST {url} -> {exc.code}") from exc
    except urllib.error.URLError as exc:  # pragma: no cover
        raise AlertError(f"POST {url} -> {exc.reason}") from exc


def send_event(sink: AlertSink, alert: Alert) -> int:
    """Deliver a single alert to one sink."""
    payload = json.dumps(alert.to_payload()).encode("utf-8")
    return _post(sink.url, payload, sink.sign(payload))


def send(sinks: Iterable[AlertSink], alert: Alert) -> dict[str, int]:
    """Deliver an alert to every sink. Returns {sink_name: status_code}."""
    results: dict[str, int] = {}
    for sink in sinks:
        try:
            results[sink.name] = send_event(sink, alert)
        except AlertError:
            results[sink.name] = 0
    return results


def from_env() -> list[AlertSink]:
    """Read ``DONTLIE_ALERT_WEBHOOKS`` (JSON list) and return sinks."""
    config = os.environ.get("DONTLIE_ALERT_WEBHOOKS", "").strip()
    if not config:
        return []
    try:
        items = json.loads(config)
    except json.JSONDecodeError as exc:
        raise AlertError(f"DONTLIE_ALERT_WEBHOOKS is not JSON: {exc}") from exc
    sinks: list[AlertSink] = []
    for item in items:
        sinks.append(
            AlertSink(
                name=item["name"],
                url=item["url"],
                secret=item.get("secret"),
                headers=item.get("headers", {}),
            )
        )
    return sinks


def alert_chain_break(receipt_id: int, reason: str) -> Alert:
    return Alert(
        title="Receipt chain break",
        body=(
            f"Receipt #{receipt_id} failed verification: {reason}. "
            "Investigate or restore from signed export."
        ),
        severity="critical",
        tags=("chain", "verification"),
    )


def alert_key_revoked(key_id: str) -> Alert:
    return Alert(
        title="Signing key revoked",
        body=f"Key {key_id[:8]} was marked revoked. Future receipts signed by this key will fail verification.",
        severity="warning",
        tags=("key", "revocation"),
    )


__all__ = [
    "Alert",
    "AlertError",
    "AlertSink",
    "alert_chain_break",
    "alert_key_revoked",
    "from_env",
    "send",
    "send_event",
]
