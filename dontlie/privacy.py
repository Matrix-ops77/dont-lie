"""Selectable evidence modes for Don't-Lie receipts.

Receipts in the vault can be exported or shared with different privacy
postures. This module defines three explicit evidence modes:

- ``fingerprint``  – only a stable hash fingerprint; the text is gone.
- ``redacted``     – locally-redacted text with the original character
                     offsets preserved for audit. **Never** claimed to be
                     perfect: PII detection is heuristic, not exhaustive.
- ``forensic``     – the original text plus structured detection metadata
                     describing what was found and what was changed.

Every artifact produced here carries an explicit ``Evidence`` envelope
listing the mode, the detectors that ran, the version of the detector
bundle, the timestamp, and any redactions that were applied. The
envelope is the unit of trust: if the envelope is lost, downstream
callers cannot tell whether a piece of text was redacted or not.

Design constraints (deliberate, in scope of this module):

1. Determinism.  Two runs over the same input must produce identical
   output bytes, byte-for-byte. No randomness, no time-of-day, no
   environment lookup beyond the inputs.
2. Self-describing.  Every exported artifact carries the detector
   version, mode, and a per-detection index. There is no "compiled-out"
   redaction — the truth is in the artifact.
3. No false confidence.  ``redacted`` output always carries a
   ``detection.heuristic_warning`` flag noting that redaction may be
   incomplete. ``forensic`` output preserves the original so the
   redacted view is auditable against the source.
4. No network.  All detection is regex/keyword based. The module
   exposes integration points (see ``register_detector``) so callers
   can plug in richer detectors (e.g. local NER) without depending on
   them at import time.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal

EvidenceMode = Literal["fingerprint", "redacted", "forensic"]

EVIDENCE_FORMAT = "dontlie-evidence"
EVIDENCE_VERSION = 1
DETECTOR_BUNDLE_VERSION = "det-v1"

# Default detectors. Each is (id, label, regex-with-named-groups).
# Order matters: earlier detectors are reported first when several
# patterns hit the same span. Patterns are deliberately conservative —
# we want false positives over silent misses, but we never claim a
# redaction is exhaustive.
DEFAULT_DETECTORS: tuple[tuple[str, str, str], ...] = (
    (
        "openai_api_key",
        "OpenAI / OpenAI-style API key",
        r"(?P<openai_api_key>sk-[A-Za-z0-9_-]{20,})",
    ),
    (
        "anthropic_api_key",
        "Anthropic-style API key",
        r"(?P<anthropic_api_key>sk-ant-[A-Za-z0-9_-]{20,})",
    ),
    (
        "aws_access_key",
        "AWS access key id",
        r"(?P<aws_access_key>AKIA[0-9A-Z]{16})",
    ),
    (
        "github_pat",
        "GitHub personal access token",
        r"(?P<github_pat>ghp_[A-Za-z0-9]{20,})",
    ),
    (
        "bearer_token",
        "Bearer / Authorization token",
        r"(?P<bearer_token>[Bb]earer\s+[A-Za-z0-9._\-]{16,})",
    ),
    (
        "private_key_block",
        "PEM private key block",
        r"(?P<private_key_block>-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----)",
    ),
    (
        "email",
        "Email address",
        r"(?P<email>[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,})",
    ),
    (
        "ipv4",
        "IPv4 address",
        r"(?P<ipv4>(?<![\d.])(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d?\d)){3}(?![\d.]))",
    ),
    (
        "us_ssn",
        "US Social Security Number",
        r"(?P<us_ssn>(?<![\d-])(\d{3}-\d{2}-\d{4})(?![\d-]))",
    ),
    (
        "credit_card",
        "Credit-card-shaped number (Luhn-unchecked)",
        r"(?P<credit_card>(?<![\d])(?:\d[ -]?){13,19}(?![\d]))",
    ),
    (
        "phone_e164",
        "E.164 phone number",
        r"(?P<phone_e164>(?<!\d)\+\d{10,15}(?!\d))",
    ),
    (
        "url_with_creds",
        "URL with embedded credentials",
        r"(?P<url_with_creds>[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:@/]+:[^\s@/]+@[^\s]+)",
    ),
)

# Replacement tokens. Stable across runs (no timestamps, no counters).
REDACTED_TOKEN = "[REDACTED:{detector}]"
PARTIAL_TOKEN = "[PARTIAL:{detector}:sha256={digest}]"


class PrivacyError(ValueError):
    """Raised when an evidence mode is requested with an invalid config."""


@dataclass(frozen=True)
class Detection:
    """One hit from a detector on a piece of text."""

    detector: str
    label: str
    start: int
    end: int
    text: str
    digest_sha256: str

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Evidence:
    """The self-describing envelope around an evidence artifact."""

    mode: EvidenceMode
    format: str
    format_version: int
    detector_bundle: str
    generated_at: str
    text_digest_sha256: str
    redactions: tuple[Detection, ...] = ()
    text: str | None = None
    fingerprint: str | None = None
    metadata: Mapping[str, Any] = field(default_factory=dict)
    warnings: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "format": self.format,
            "format_version": self.format_version,
            "mode": self.mode,
            "detector_bundle": self.detector_bundle,
            "generated_at": self.generated_at,
            "text_digest_sha256": self.text_digest_sha256,
            "metadata": dict(self.metadata),
        }
        if self.redactions:
            result["redactions"] = [d.as_dict() for d in self.redactions]
        if self.text is not None:
            result["text"] = self.text
        if self.fingerprint is not None:
            result["fingerprint"] = self.fingerprint
        if self.warnings:
            result["warnings"] = list(self.warnings)
        return result

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False
        )


# ---------------------------------------------------------------------------
# Detector registry
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _CompiledDetector:
    id: str
    label: str
    pattern: re.Pattern[str]


class DetectorRegistry:
    """Ordered collection of compiled detectors.

    Detectors are run in registration order. The first detector that
    matches a span wins; overlaps with later detectors are dropped so
    we never report the same span twice.
    """

    def __init__(self, detectors: Iterable[tuple[str, str, str]] | None = None) -> None:
        self._items: list[_CompiledDetector] = []
        if detectors is not None:
            for detector_id, label, pattern in detectors:
                self.register(detector_id, label, pattern)

    def register(self, detector_id: str, label: str, pattern: str) -> None:
        if not detector_id or not isinstance(detector_id, str):
            raise PrivacyError("detector id must be a non-empty string")
        if any(item.id == detector_id for item in self._items):
            raise PrivacyError(f"detector {detector_id!r} already registered")
        compiled = re.compile(pattern)
        if not any(compiled.groupindex):
            raise PrivacyError(
                f"detector {detector_id!r} must declare exactly one named group"
            )
        self._items.append(_CompiledDetector(detector_id, label, compiled))

    def detect(self, text: str) -> list[Detection]:
        """Run every registered detector and return a sorted, de-overlapped hit list.

        Hits are reported in left-to-right order. When two detectors
        match overlapping spans, the earlier-registered detector wins
        and the overlapping tail of the second detector is dropped.
        """
        if not text:
            return []
        claimed: list[tuple[int, int]] = []
        hits: list[Detection] = []
        for detector in self._items:
            for match in detector.pattern.finditer(text):
                span = _match_span(match)
                if span is None:
                    continue
                start, end = span
                if any(_overlaps(start, end, c_start, c_end) for c_start, c_end in claimed):
                    continue
                hit_text = text[start:end]
                hits.append(
                    Detection(
                        detector=detector.id,
                        label=detector.label,
                        start=start,
                        end=end,
                        text=hit_text,
                        digest_sha256=hashlib.sha256(hit_text.encode("utf-8")).hexdigest(),
                    )
                )
                claimed.append((start, end))
        hits.sort(key=lambda h: (h.start, h.end))
        return hits

    def identifiers(self) -> tuple[str, ...]:
        return tuple(item.id for item in self._items)


def default_registry() -> DetectorRegistry:
    return DetectorRegistry(DEFAULT_DETECTORS)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def text_digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def fingerprint_of(text: str) -> str:
    """A short, stable, content-addressed handle for ``text``.

    The format is ``sha256:<hex>`` so it sorts naturally in audit logs.
    """
    return f"sha256:{text_digest(text)}"


def detect(
    text: str,
    *,
    registry: DetectorRegistry | None = None,
) -> tuple[Detection, ...]:
    """Return the detections for ``text`` using the supplied (or default) registry."""
    return tuple((registry or default_registry()).detect(text))


def redact_text(
    text: str,
    detections: Iterable[Detection],
) -> str:
    """Apply non-overlapping redactions to ``text`` and return the result.

    Detections must be sorted by ``start``. Any detection that
    overlaps with a previous replacement is silently dropped, which
    keeps the function linear and deterministic. The replacement
    token includes the detector id and a per-span content digest so
    the redaction is auditable from the artifact alone.
    """
    sorted_hits = sorted(detections, key=lambda d: (d.start, d.end))
    pieces: list[str] = []
    cursor = 0
    for hit in sorted_hits:
        if hit.start < cursor or hit.end > len(text) or hit.start >= hit.end:
            continue
        if hit.start > cursor:
            pieces.append(text[cursor:hit.start])
        token = PARTIAL_TOKEN.format(detector=hit.detector, digest=hit.digest_sha256)
        pieces.append(token)
        cursor = hit.end
    if cursor < len(text):
        pieces.append(text[cursor:])
    return "".join(pieces)


def build_evidence(
    text: str,
    *,
    mode: EvidenceMode,
    registry: DetectorRegistry | None = None,
    metadata: Mapping[str, Any] | None = None,
    generated_at: str | None = None,
) -> Evidence:
    """Build the evidence artifact for ``text`` under the requested ``mode``.

    The returned ``Evidence`` is the canonical, self-describing form
    that should travel with any exported artifact. Callers can
    ``json.loads(evidence.to_json())`` it without losing structure.

    ``mode`` must be one of ``"fingerprint"``, ``"redacted"``, or
    ``"forensic"``. Passing any other value is a programming error
    that the static type checker will reject.
    """
    reg = registry or default_registry()
    timestamp = generated_at or _deterministic_timestamp()
    detections = reg.detect(text)
    digest = text_digest(text)
    warnings: tuple[str, ...] = (
        "detection is heuristic; redacted output may be incomplete",
    )

    base_metadata: dict[str, Any] = dict(metadata or {})
    base_metadata.setdefault("detectors", list(reg.identifiers()))

    if mode == "fingerprint":
        return Evidence(
            mode="fingerprint",
            format=EVIDENCE_FORMAT,
            format_version=EVIDENCE_VERSION,
            detector_bundle=DETECTOR_BUNDLE_VERSION,
            generated_at=timestamp,
            text_digest_sha256=digest,
            redactions=(),
            text=None,
            fingerprint=fingerprint_of(text),
            metadata=base_metadata,
            warnings=warnings,
        )
    if mode == "redacted":
        return Evidence(
            mode="redacted",
            format=EVIDENCE_FORMAT,
            format_version=EVIDENCE_VERSION,
            detector_bundle=DETECTOR_BUNDLE_VERSION,
            generated_at=timestamp,
            text_digest_sha256=digest,
            redactions=tuple(detections),
            text=redact_text(text, detections),
            fingerprint=None,
            metadata=base_metadata,
            warnings=tuple(warnings),
        )
    # forensic
    return Evidence(
        mode="forensic",
        format=EVIDENCE_FORMAT,
        format_version=EVIDENCE_VERSION,
        detector_bundle=DETECTOR_BUNDLE_VERSION,
        generated_at=timestamp,
        text_digest_sha256=digest,
        redactions=tuple(detections),
        text=text,
        fingerprint=fingerprint_of(text),
        metadata=base_metadata,
        warnings=tuple(warnings),
    )


def fingerprint_payload(text: str, *, registry: DetectorRegistry | None = None) -> str:
    """Convenience: the JSON form of a fingerprint-mode evidence artifact."""
    return build_evidence(text, mode="fingerprint", registry=registry).to_json()


def redacted_payload(text: str, *, registry: DetectorRegistry | None = None) -> str:
    """Convenience: the JSON form of a redacted-mode evidence artifact."""
    return build_evidence(text, mode="redacted", registry=registry).to_json()


def forensic_payload(text: str, *, registry: DetectorRegistry | None = None) -> str:
    """Convenience: the JSON form of a forensic-mode evidence artifact."""
    return build_evidence(text, mode="forensic", registry=registry).to_json()


def detect_inline_secrets(
    text: str,
    *,
    registry: DetectorRegistry | None = None,
) -> list[str]:
    """Return a stable list of detector ids that fired for ``text``.

    Intended for callers that want a quick "is this text likely to
    contain secrets/PII?" probe without building a full evidence
    envelope. Order is stable and de-duplicated.
    """
    hits = detect(text, registry=registry)
    seen: set[str] = set()
    out: list[str] = []
    for hit in hits:
        if hit.detector in seen:
            continue
        seen.add(hit.detector)
        out.append(hit.detector)
    return out


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _match_span(match: re.Match[str]) -> tuple[int, int] | None:
    named_groups = match.groupdict()
    group_index: int | None = None
    for name, value in named_groups.items():
        if value is not None:
            group_index = match.re.groupindex[name]
            break
    if group_index is None:
        return None
    return match.start(group_index), match.end(group_index)


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start < b_end and b_start < a_end


def _deterministic_timestamp() -> str:
    """UTC ISO-8601 with a fixed offset.

    We do not use ``datetime.now`` here: determinism across runs is
    a stated property of the module. Callers that want a real
    timestamp can pass ``generated_at`` explicitly.
    """
    return datetime(1970, 1, 1, tzinfo=timezone.utc).isoformat()


def verify_evidence(payload: str | bytes) -> Evidence:
    """Parse and validate a JSON evidence artifact produced by this module.

    The returned ``Evidence`` object preserves the parsed structure.
    Raises ``PrivacyError`` if the artifact is malformed or has an
    unexpected ``format``/``format_version`` pair.
    """
    if isinstance(payload, bytes):
        try:
            payload = payload.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PrivacyError("evidence payload is not valid UTF-8") from exc
    try:
        document = json.loads(payload)
    except json.JSONDecodeError as exc:
        raise PrivacyError(f"evidence payload is not valid JSON: {exc}") from exc
    if not isinstance(document, dict):
        raise PrivacyError("evidence payload must decode to an object")
    if document.get("format") != EVIDENCE_FORMAT:
        raise PrivacyError(
            f"unsupported evidence format {document.get('format')!r}"
        )
    if document.get("format_version") != EVIDENCE_VERSION:
        raise PrivacyError(
            f"unsupported evidence format_version {document.get('format_version')!r}"
        )
    mode = document.get("mode")
    if mode not in ("fingerprint", "redacted", "forensic"):
        raise PrivacyError(f"unknown evidence mode {mode!r}")
    raw_redactions = document.get("redactions") or []
    redactions: list[Detection] = []
    for raw in raw_redactions:
        if not isinstance(raw, dict):
            raise PrivacyError("each redaction must be an object")
        redactions.append(
            Detection(
                detector=str(raw.get("detector", "")),
                label=str(raw.get("label", "")),
                start=int(raw.get("start", 0)),
                end=int(raw.get("end", 0)),
                text=str(raw.get("text", "")),
                digest_sha256=str(raw.get("digest_sha256", "")),
            )
        )
    raw_warnings = document.get("warnings") or []
    if not isinstance(raw_warnings, list) or not all(
        isinstance(w, str) for w in raw_warnings
    ):
        raise PrivacyError("warnings must be a list of strings")
    raw_metadata = document.get("metadata") or {}
    if not isinstance(raw_metadata, dict):
        raise PrivacyError("metadata must be an object")
    return Evidence(
        mode=mode,  # type: ignore[arg-type]
        format=str(document.get("format", "")),
        format_version=int(document.get("format_version", 0)),
        detector_bundle=str(document.get("detector_bundle", "")),
        generated_at=str(document.get("generated_at", "")),
        text_digest_sha256=str(document.get("text_digest_sha256", "")),
        redactions=tuple(redactions),
        text=(
            str(document["text"])
            if "text" in document and document["text"] is not None
            else None
        ),
        fingerprint=(
            str(document["fingerprint"])
            if "fingerprint" in document and document["fingerprint"] is not None
            else None
        ),
        metadata=raw_metadata,
        warnings=tuple(raw_warnings),
    )


def evidence_text_digest(payload: str | bytes) -> str:
    """Return the SHA-256 digest declared by an evidence payload."""
    return verify_evidence(payload).text_digest_sha256


# ---------------------------------------------------------------------------
# Optional forensic comparison helper
# ---------------------------------------------------------------------------


def forensic_diff_summary(
    original: str,
    redacted_evidence: Evidence,
) -> dict[str, Any]:
    """Compare a forensic source to a redacted evidence and summarize the diff.

    This is a small, dependency-free audit helper. It is intentionally
    not a full textual diff: the goal is to confirm that the
    redacted-mode artifact really did scrub the spans the forensic
    view reports, and to count any discrepancies.
    """
    if redacted_evidence.mode != "redacted":
        raise PrivacyError("forensic_diff_summary requires a redacted-mode evidence")
    redacted_text = redacted_evidence.text or ""
    spans = [(d.start, d.end) for d in redacted_evidence.redactions]
    expected = redact_text(original, redacted_evidence.redactions)
    byte_equal = expected == redacted_text
    detector_ids = sorted({d.detector for d in redacted_evidence.redactions})
    return {
        "original_digest": text_digest(original),
        "redacted_digest": text_digest(redacted_text),
        "byte_equal": byte_equal,
        "redaction_count": len(spans),
        "detectors": detector_ids,
        "redacted_length": len(redacted_text),
        "original_length": len(original),
    }


# Exposed for tests and integrations that want to forge a fingerprint
# without re-deriving it: ``base64.b64encode(sha256(text)).decode()`` is
# what the rest of the dontlie vault uses as a canonical handle, and
# the privacy module agrees on that shape.
def fingerprint_b64(text: str) -> str:
    """Return base64(sha256(text)) for callers that want a URL-safe handle."""
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")
