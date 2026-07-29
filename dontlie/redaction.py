"""Secret redaction for Don't-Lie receipts.

Detects high-risk secrets in prompt/response payloads before they are
persisted to the signed receipt chain. The redaction layer is best-effort:

* It is a policy decision, not a probabilistic classifier; missed secrets
  are missed, not flagged.
* It does not modify cryptographic guarantees: redacted values are *replaced*
  with a deterministic token so receipts still verify (the SHA-256 of the
  payload is computed over the redacted string).
* It is independent from the verifier; downstream readers see ``[REDACTED:
  OPENAI_API_KEY]`` instead of the raw secret.

Patterns covered:

- ``OPENAI_API_KEY``           — ``sk-...``, ``sk-proj-...``
- ``ANTHROPIC_API_KEY``        — ``sk-ant-...``
- ``AWS_ACCESS_KEY_ID``        — 20-char base64
- ``GOOGLE_API_KEY``           — ``AIza...``
- ``GITHUB_TOKEN``             — ``ghp_...``, ``gho_...``, ``ghs_...``
- ``SLACK_TOKEN``              — ``xox[abprs]-...``
- ``STRIPE_API_KEY``           — ``sk_live_...``, ``pk_live_...``
- ``EMAIL``                    — ``addr@host.tld``
- ``SSN``                      — ``NNN-NN-NNNN``
- ``CREDIT_CARD``              — 13–19 digit PAN, with Luhn check
- ``PHONE``                    — international + US phone-ish
- ``JWT``                      — 3-segment base64url
- ``PRIVATE_KEY_BLOCK``        — ``-----BEGIN ... PRIVATE KEY-----``
- ``BASIC_AUTH``               — ``Basic <base64>``

The policy is intentionally conservative: fewer false positives, more
operator trust. Keep this list aligned with your customer-base risk
profile; add a detector rather than loosen an existing one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable


@dataclass(frozen=True)
class Detection:
    rule: str
    start: int
    end: int
    token: str

    def __str__(self) -> str:  # pragma: no cover - debug only
        return f"{self.rule}@{self.start}-{self.end}"


@dataclass
class RedactionReport:
    text: str
    detections: list[Detection] = field(default_factory=list)

    @property
    def redacted(self) -> bool:
        return bool(self.detections)

    def to_extra(self) -> dict:
        """Embed as receipt metadata."""
        return {
            "redacted": self.redacted,
            "rules": sorted({d.rule for d in self.detections}),
            "count": len(self.detections),
        }


class RedactionPolicy:
    """Apply a fixed set of regex detectors to a string."""

    def __init__(self, rules: Iterable[str] | None = None) -> None:
        from . import patterns  # local import to keep top-level lightweight

        self._patterns = patterns.build_default_patterns()
        self._enabled = set(rules) if rules else set(self._patterns.keys())
        self._luhn = patterns.luhn_check

    def detect(self, text: str) -> list[Detection]:
        detections: list[Detection] = []
        for rule, pattern in self._patterns.items():
            if rule not in self._enabled:
                continue
            for match in pattern.finditer(text):
                if rule == "CREDIT_CARD" and not self._luhn(match.group(1)):
                    continue
                token = f"[REDACTED:{rule}]"
                detections.append(Detection(rule, match.start(), match.end(), token))
        return self._merge(detections)

    def apply(self, text: str) -> RedactionReport:
        detections = self.detect(text)
        if not detections:
            return RedactionReport(text=text, detections=[])
        # Reverse-iterate so indices remain stable.
        redacted = text
        for det in reversed(detections):
            redacted = redacted[: det.start] + det.token + redacted[det.end :]
        return RedactionReport(text=redacted, detections=detections)

    @staticmethod
    def _merge(detections: list[Detection]) -> list[Detection]:
        """Drop overlapping detections; keep the earliest / longest rule."""
        detections.sort(key=lambda d: (d.start, -(d.end - d.start)))
        merged: list[Detection] = []
        last_end = -1
        for det in detections:
            if det.start < last_end:
                continue
            merged.append(det)
            last_end = det.end
        return merged


__all__ = ["Detection", "RedactionPolicy", "RedactionReport"]
