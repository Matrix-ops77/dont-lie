"""dontlie/verify_url.py — self-contained shareable verification URLs.

Generates a URL like:

    <operator-supplied-base-url>/#v=BASE64URL(JSON)

Where the JSON is a single-receipt portable bundle. The base URL is
supplied by the operator (typically the URL of the verifier they
operate — the shipped `site/demo.html` Browser Proof Lab, or a self-
hosted verifier). Anyone with the URL can open it in a browser and
verify the receipt entirely client-side, with no network calls, no
server, and no Dont-Lie account.

This is a key unfair-advantage: the receipt and the verification
tools travel together in a single link. The user can paste the URL
into a chat, an email, a regulatory submission, or a court exhibit.
The verifier (the deployed static site) holds the keys to verifying
it; the receipt travels with itself.

URL format spec (v1):

    Fragment is a single key=value pair, ``v=<base64url(json)>``
    where the JSON has the shape:

    {
      "v": 1,                     # URL format version
      "url": "<operator-supplied verifier URL>",  # the base URL the operator chose
      "issued_at": "2026-07-29T...",        # when the URL was generated
      "receipt": {
        "id": int,
        "timestamp": str,
        "model": str,
        "prompt": str,
        "response": str,
        "parent_id": int | None,
        "key_id": str,
        "payload_sha256": str,
        "tags": list,
        "extra": dict,
        "operator_id": str | None,   # v3 chain only
        "deployer_id": str | None,   # v3 chain only
        "system_id": str | None,     # v3 chain only
        "body_canon": str,           # the canonical JSON that was signed
        "signature": str,            # base64-encoded Ed25519 sig
      },
      "public_key_pem": "-----BEGIN PUBLIC KEY-----\\n..."
    }

The verifier (deployed static site) decodes the fragment, rebuilds
the canonical payload from the receipt fields, and verifies the
Ed25519 signature with the embedded public key.

If a future version of this format is incompatible, bump ``v`` to 2
and the verifier will reject v1 URLs (or vice versa).
"""
from __future__ import annotations

import base64
import binascii
import json
import os
from typing import Any
from urllib.parse import urlparse, urlunparse

from . import sign as signing
from . import storage

FORMAT_VERSION = 1
# Where the embedded verify URL points by default. There is no
# Don't-Lie-operated verifier; the operator passes --base-url or
# sets $DONTLIE_VERIFY_URL_BASE. The CLI's default is a blank
# string — the operator must supply their own.
DEFAULT_VERIFIER_URL = os.environ.get("DONTLIE_VERIFY_URL_BASE", "")
# Path on the verifier URL where the verify-hash flow lives. The
# canonical implementation is `site/demo.html` (the Browser Proof
# Lab) which reads the hash fragment on page load. If the operator
# runs their own verifier, they point --base-url at it.
DEFAULT_VERIFIER_PATH = "/"


def _b64url_encode(data: bytes) -> str:
    """Base64-url encode without padding (URL-safe)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Base64-url decode (with or without padding)."""
    # Re-add stripped padding
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def build_payload(receipt: storage.Receipt, base_url: str = "") -> dict[str, Any]:
    """Build the JSON dict that gets encoded into the URL.

    The dict is JSON-serializable. The caller is responsible for
    base64url-encoding and adding the URL prefix. The ``base_url``
    is the verifier URL the operator chose to embed; it is the
    ``url`` field of the encoded payload and is operator-supplied,
    not operator-defaulted.
    """
    # The canonical form is the exact bytes the signer signed.
    body_canon = storage._canonical_payload(receipt).decode("utf-8")
    rec_dict: dict[str, Any] = {
        "id": receipt.id,
        "timestamp": receipt.timestamp,
        "model": receipt.model,
        "prompt": receipt.prompt,
        "response": receipt.response,
        "parent_id": receipt.parent_id,
        "key_id": receipt.key_id,
        "payload_sha256": receipt.payload_sha256,
        "tags": list(receipt.tags),
        "extra": dict(receipt.extra),
        "body_canon": body_canon,
        "signature": receipt.signature,
    }
    # Include v3 fields if present
    if receipt.operator_id is not None or receipt.deployer_id is not None or receipt.system_id is not None:
        rec_dict["operator_id"] = receipt.operator_id
        rec_dict["deployer_id"] = receipt.deployer_id
        rec_dict["system_id"] = receipt.system_id

    return {
        "v": FORMAT_VERSION,
        "url": base_url,
        "issued_at": _now_iso(),
        "receipt": rec_dict,
        "public_key_pem": signing.public_key_pem(),
    }


def _now_iso() -> str:
    from datetime import datetime, timezone

    return datetime.now(timezone.utc).isoformat()


def encode_url(receipt: storage.Receipt, base_url: str = DEFAULT_VERIFIER_URL) -> str:
    """Build a shareable URL for one receipt.

    Args:
        receipt: the receipt to encode
        base_url: the verifier URL (default: $DONTLIE_VERIFY_URL_BASE or empty)

    Returns:
        a full URL with the receipt data in the fragment, ready to
        paste into chat, email, or a regulatory submission. The
        URL must point at a verifier the operator has vetted —
        there is no Don't-Lie-operated verifier service.
    """
    if not base_url:
        raise ValueError(
            "verifier URL is required: pass --base-url or set $DONTLIE_VERIFY_URL_BASE"
        )
    payload = build_payload(receipt, base_url=base_url)
    json_bytes = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    encoded = _b64url_encode(json_bytes)

    parsed = urlparse(base_url)
    # Always use no path; the hash is the only data the verifier needs.
    new = urlunparse((parsed.scheme, parsed.netloc, DEFAULT_VERIFIER_PATH, "", "", ""))
    return f"{new}#v={encoded}"


def decode_fragment(fragment: str) -> dict[str, Any]:
    """Parse a URL fragment (everything after #v=) back into the payload dict.

    Raises:
        ValueError: if the fragment is malformed or the format version
            is unsupported.
    """
    if fragment.startswith("v="):
        fragment = fragment[2:]
    elif fragment.startswith("#v="):
        fragment = fragment[3:]

    try:
        raw = _b64url_decode(fragment)
    except (binascii.Error, ValueError) as exc:
        raise ValueError(f"verify URL fragment is not valid base64url: {exc}") from exc

    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"verify URL payload is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise TypeError("verify URL payload must be a JSON object")
    fmt_version = payload.get("v")
    if fmt_version != FORMAT_VERSION:
        raise ValueError(
            f"verify URL format version {fmt_version!r} not supported "
            f"(this verifier only understands v={FORMAT_VERSION})"
        )
    if "receipt" not in payload:
        raise ValueError("verify URL payload is missing the 'receipt' field")
    if "public_key_pem" not in payload:
        raise ValueError("verify URL payload is missing the 'public_key_pem' field")
    return payload


def verify_payload_locally(payload: dict[str, Any]) -> tuple[bool, str]:
    """Verify a payload dict (from decode_fragment) without the web UI.

    Returns (ok, reason). reason is empty when ok=True.
    """
    rec = payload["receipt"]
    pub_pem = payload["public_key_pem"]
    # Re-derive the canonical payload from the receipt fields
    chain_version = (rec.get("extra") or {}).get(storage.CHAIN_VERSION_KEY)
    obj: dict[str, Any] = {
        "id": rec["id"],
        "timestamp": rec["timestamp"],
        "model": rec["model"],
        "prompt": rec["prompt"],
        "response": rec["response"],
        "parent_id": rec.get("parent_id"),
        "key_id": rec["key_id"],
        "tags": rec.get("tags", []),
        "extra": rec.get("extra", {}),
    }
    if chain_version is not None and chain_version >= 3:
        obj["operator_id"] = rec.get("operator_id")
        obj["deployer_id"] = rec.get("deployer_id")
        obj["system_id"] = rec.get("system_id")
    derived_canon = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    # Compare to the included body_canon
    if rec.get("body_canon") and rec["body_canon"].encode("utf-8") != derived_canon:
        return False, "body_canon does not match the canonical form derived from the receipt fields"

    # Verify the signature
    try:
        pub = signing.load_public_key(pub_pem)
    except Exception as exc:
        return False, f"could not load public key: {exc}"
    # verify_bytes returns False on bad signature (it does not raise);
    # we need to check the return value, not just catch exceptions.
    if not signing.verify_bytes(pub, derived_canon, rec["signature"]):
        return False, "Ed25519 signature did not verify against the canonical payload"

    # Optionally verify parent chain link (if parent_id is provided, we
    # need a parent_sha256; we don't have that in the URL but the body_canon
    # embeds payload_sha256 — that's a separate field, not the parent's)
    return True, ""


def main(argv: list[str] | None = None) -> int:
    """CLI entry: dontlie verify-url <id> [--base-url URL] [--out FILE]"""
    import argparse
    import sys

    p = argparse.ArgumentParser(
        prog="dontlie verify-url",
        description="Generate a self-contained, shareable verification URL for one receipt.",
    )
    p.add_argument("receipt_id", type=int, help="the receipt id to encode")
    p.add_argument(
        "--base-url",
        default=DEFAULT_VERIFIER_URL,
        help=f"verifier URL to embed (default: {DEFAULT_VERIFIER_URL})",
    )
    p.add_argument(
        "--out",
        default=None,
        help="write URL to this file instead of stdout",
    )
    p.add_argument(
        "--verify",
        action="store_true",
        help="verify the generated URL locally before emitting (sanity check)",
    )
    args = p.parse_args(argv)

    receipt = storage.get_receipt(args.receipt_id)
    if receipt is None:
        print(f"receipt #{args.receipt_id} not found", file=sys.stderr)
        return 1

    url = encode_url(receipt, base_url=args.base_url)
    if args.verify:
        # Parse the URL back and verify
        fragment = url.split("#", 1)[1]
        payload = decode_fragment(fragment)
        ok, reason = verify_payload_locally(payload)
        if not ok:
            print(f"local verify failed: {reason}", file=sys.stderr)
            return 2
        print(f"local verify OK · URL is {len(url)} chars", file=sys.stderr)

    if args.out:
        Path(args.out).write_text(url + "\n")
        print(f"wrote verify URL to {args.out}", file=sys.stderr)
    else:
        print(url)
    return 0


from pathlib import Path  # imported here to keep the module-level imports tidy

if __name__ == "__main__":
    raise SystemExit(main())
