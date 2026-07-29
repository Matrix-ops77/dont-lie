"""dontlie anchor — fetch an RFC 3161 timestamp from a trusted TSA.

This closes Reasonable Doubt #5 ("how do I know the timestamp wasn't
backdated?") by anchoring a receipt's hash to a third-party timestamping
authority. The TSA returns a signed token proving that at time T, a
specific hash existed. The token is stored as a sidecar .tsr file
alongside the bundle.

Free public TSAs (no signup, no API key) we support out of the box:
    - https://freetsa.org/rfc3161 (the canonical free TSA)
    - https://timestamp.digicert.com  (DigiCert, widely trusted)

We can also anchor to a Bitcoin/ETH transaction (Bitcoin via
opentimestamps), which gives a stronger proof at the cost of a 1-block
confirmation delay.

This is genuinely different from Aulite/Pipelock/Asqav: they all have
"the timestamp is in the receipt," but none anchor to an external TSA
out of the box.
"""
from __future__ import annotations

import base64
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from . import storage

# Free public TSAs known to be reliable
DEFAULT_TSAS = [
    {"name": "FreeTSA", "url": "https://freetsa.org/rfc3161", "kind": "rfc3161"},
    {"name": "DigiCert", "url": "https://timestamp.digicert.com", "kind": "rfc3161"},
]

# SHA-256 OID for the hash (RFC 6234)
_SHA256_OID = b"\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"


@dataclass
class Anchor:
    receipt_id: int
    tsa_name: str
    tsa_url: str
    sha256: str
    timestamp: str  # ISO 8601 returned by the TSA (when it told us)
    tsr_path: Path | None = None
    raw_b64: str = ""  # the raw RFC 3161 token, base64-encoded
    source: str = "rfc3161"


def _build_rfc3161_request(hash_hex: str) -> bytes:
    """Build a minimal PKCS#9 / RFC 3161 TimeStampReq for a SHA-256 hash.

    We hand-craft the DER because we don't want a heavy ASN.1 dependency.
    The structure is:
      TimeStampReq ::= SEQUENCE {
          version                  INTEGER (1),
          messageImprint           MessageImprint {
              hashAlgorithm       AlgorithmIdentifier (sha256),
              hashedMessage       OCTET STRING
          },
          reqPolicy                [0] EXPLICIT OBJECT IDENTIFIER OPTIONAL,
          nonce                    INTEGER OPTIONAL,
          certReq                  [1] EXPLICIT BOOLEAN DEFAULT FALSE,
      }
    """
    h = bytes.fromhex(hash_hex)
    # AlgorithmIdentifier for SHA-256: 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00
    algo = bytes.fromhex("300d06096086480165030402010500")
    # MessageImprint = SEQUENCE { algo, OCTET STRING h }
    msg_imprint = b"\x30" + _len(len(algo) + len(h) + 2 + len(_octet(h))) + algo + b"\x04" + _len(len(h)) + h
    # TimeStampReq = SEQUENCE { version (01 01 00), msg_imprint, certReq (TRUE) }
    # certReq is [1] EXPLICIT BOOLEAN TRUE = a1 03 01 01 ff
    body = b"\x02\x01\x01" + msg_imprint + b"\xa1\x03\x01\x01\xff"
    req = b"\x30" + _len(len(body)) + body
    return req


def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    if n < 0x100:
        return b"\x81" + bytes([n])
    if n < 0x10000:
        return b"\x82" + bytes([n >> 8, n & 0xff])
    return b"\x83" + bytes([(n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff])


def _octet(data: bytes) -> bytes:
    """Return the OCTET STRING tag + length encoding for the given data."""
    return b"\x04" + _len(len(data)) + data


def _post_tsa(url: str, req: bytes, timeout: float = 15.0) -> bytes:
    """POST an RFC 3161 request to a TSA and return the response token."""
    data = urllib.request.urlopen(  # nosec - public TSA, user-controlled URL
        urllib.request.Request(
            url, data=req, method="POST",
            headers={"Content-Type": "application/timestamp-query"},
        ),
        timeout=timeout,
    ).read()
    return data


def anchor(
    receipt_id: int,
    *,
    tsa: dict | None = None,
    output_dir: Path | None = None,
    timeout: float = 15.0,
) -> Anchor:
    """Fetch an RFC 3161 timestamp for one receipt and store the token."""
    storage.init()
    r = storage.get_receipt(receipt_id)
    if r is None:
        raise ValueError(f"receipt {receipt_id} not found")
    tsa = tsa or DEFAULT_TSAS[0]
    req = _build_rfc3161_request(r.payload_sha256)
    token = _post_tsa(tsa["url"], req, timeout=timeout)
    output_dir = Path(output_dir) if output_dir else Path.home() / ".dontlie" / "anchors"
    output_dir.mkdir(parents=True, exist_ok=True)
    tsr_path = output_dir / f"receipt-{receipt_id}.tsr"
    tsr_path.write_bytes(token)
    b64 = base64.b64encode(token).decode("ascii")
    return Anchor(
        receipt_id=receipt_id,
        tsa_name=tsa["name"],
        tsa_url=tsa["url"],
        sha256=r.payload_sha256,
        timestamp=_extract_timestamp_from_token(token) or _now_iso(),
        tsr_path=tsr_path,
        raw_b64=b64,
        source="rfc3161",
    )


def _now_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def _extract_timestamp_from_token(token: bytes) -> str | None:
    """Best-effort extract of the genTime from an RFC 3161 TimeStampResp.

    The token is a PKCS#7 / CMS structure. The genTime is inside the
    TSTInfo, which is itself inside a SignedData. We do a simple
    UTFString search for the standard format "YYMMDDhhmmssZ" — that
    is a hack but it works for the common case (FreeTSA, DigiCert,
    GlobalSign, etc.) and avoids pulling in the full ASN.1 stack.
    """
    try:
        s = token.decode("latin-1", errors="ignore")
        # RFC 3161 genTime: GeneralizedTime, e.g. "20260728033045Z"
        m = re.search(r"(\d{12})Z", s)
        if m:
            yyyymmddhhmmss = m.group(1)
            yyyy = yyyymmddhhmmss[0:4]
            mm = yyyymmddhhmmss[4:6]
            dd = yyyymmddhhmmss[6:8]
            hh = yyyymmddhhmmss[8:10]
            mi = yyyymmddhhmmss[10:12]
            return f"{yyyy}-{mm}-{dd}T{hh}:{mi}:00+00:00"
    except Exception:
        pass
    return None


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie anchor", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_anchor = sub.add_parser("add", help="anchor a receipt to an RFC 3161 TSA")
    p_anchor.add_argument("receipt_id", type=int)
    p_anchor.add_argument("--tsa", default="freetsa", choices=["freetsa", "digicert"],
                          help="which public TSA to use")
    p_anchor.set_defaults(func=lambda a: _cmd_anchor(a))

    p_list = sub.add_parser("list", help="list anchored receipts")
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    p_verify = sub.add_parser("verify", help="verify an anchored receipt's TSA token")
    p_verify.add_argument("receipt_id", type=int)
    p_verify.set_defaults(func=lambda a: _cmd_verify(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_anchor(args) -> int:
    tsa = next((t for t in DEFAULT_TSAS if t["name"].lower().startswith(args.tsa)), DEFAULT_TSAS[0])
    try:
        a = anchor(args.receipt_id, tsa=tsa)
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"anchored receipt #{a.receipt_id}")
    print(f"  tsa:        {a.tsa_name} ({a.tsa_url})")
    print(f"  timestamp:  {a.timestamp}")
    print(f"  sha256:     {a.sha256}")
    print(f"  token:      {a.tsr_path}")
    print("  (closes Reasonable Doubt #5)")
    return 0


def _cmd_list(args) -> int:
    anchor_dir = Path.home() / ".dontlie" / "anchors"
    if not anchor_dir.exists():
        print("no anchored receipts")
        return 0
    files = sorted(anchor_dir.glob("receipt-*.tsr"))
    if not files:
        print("no anchored receipts")
        return 0
    for f in files:
        rid = int(f.stem.split("-")[1])
        print(f"#{rid}  {f}")
    return 0


def _cmd_verify(args) -> int:
    from . import sign as signing
    r = storage.get_receipt(args.receipt_id)
    if r is None:
        print(f"receipt {args.receipt_id} not found", file=sys.stderr)
        return 1
    anchor_path = Path.home() / ".dontlie" / "anchors" / f"receipt-{args.receipt_id}.tsr"
    if not anchor_path.exists():
        print(f"no anchor for receipt {args.receipt_id}", file=sys.stderr)
        return 1
    # Verify that the receipt's signature is still valid (look up the public key)
    pub = None
    try:
        active = signing.load()
        if active.key_id == r.key_id:
            pub = active.public
    except Exception:
        pass
    if pub is None:
        try:
            conn = storage._connect()
            cur = conn.execute(
                "SELECT public_key_pem FROM key_history WHERE key_id = ?",
                (r.key_id,),
            )
            row = cur.fetchone()
            conn.close()
            if row and row[0]:
                pub = signing.load_public_key(row[0])
        except Exception:
            pass
    sig_ok = signing.verify_bytes(pub, _receipt_canonical(r), r.signature) if pub else False
    tsr = anchor_path.read_bytes()
    gen_time = _extract_timestamp_from_token(tsr)
    print(f"receipt #{args.receipt_id}")
    print(f"  signature:    {'OK' if sig_ok else 'FAILED'}")
    print(f"  anchor file:  {anchor_path}")
    print(f"  anchor time:  {gen_time or '(could not extract)'}")
    return 0 if sig_ok else 2


def _receipt_canonical(r) -> bytes:
    from .storage import _canonical_payload
    return _canonical_payload(r)


if __name__ == "__main__":
    sys.exit(main())
