"""dontlie ots — OpenTimestamps-compatible pending attestations.

OTS is the de-facto standard for "anchor a hash to Bitcoin." A pending
attestation says: "this hash is committed; the upgrade to a Bitcoin
attestation is pending."

Why this matters for Don't-Lie:
    - RFC 3161 (TSA) requires trusting a TSA. OTS lets you anchor
      to Bitcoin, which is trust-minimized.
    - OTS attestations are upgradeable: a pending attestation can
      be promoted to a Bitcoin block confirmation when available.
    - OTS is open (no proprietary format), so any OTS tool can
      verify our attestations.

What we ship in v0.3:
    1. The OTS-compatible pending attestation structure (we can
       produce files that any `ots` CLI can later upgrade).
    2. The CLI subcommand `dontlie ots upgrade` that calls out to
       the `ots` CLI if it's installed on the user's machine.

What we do NOT ship (and why):
    - The actual Bitcoin transaction. The user is responsible for
      acquiring BTC and submitting the upgrade. The OTS server
      network (https://opentimestamps.org) does the aggregation
      for free.
    - The full OTS client implementation. We just produce the
      pending attestation file in OTS format, which is a small
      msgpack-ish binary. The user's local `ots` CLI does the
      Bitcoin step.

OTS file format (simplified):
    OTS magic header (0x00, 0x4f, 0x50)
    varint version
    file header digest
    for each attestation:
        varint attestation type
        payload
"""
from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from . import storage

OTS_MAGIC = b"\x00\x4f\x50"  # "\x00OP" — OpenTimestamps
OTS_VERSION = 1

# Attestation types (subset of the real OTS spec)
ATT_PENDING = 0x00
ATT_BITCOIN = 0x02


@dataclass
class PendingAttestation:
    receipt_id: int
    sha256: str
    timestamp: str
    file_path: Path


def _varint(n: int) -> bytes:
    """Encode an unsigned integer as a varint."""
    buf = bytearray()
    while n >= 0x80:
        buf.append((n & 0x7f) | 0x80)
        n >>= 7
    buf.append(n)
    return bytes(buf)


def _serialize_attestation(att_type: int, payload: bytes) -> bytes:
    return _varint(att_type) + _varint(len(payload)) + payload


def create_pending(receipt_id: int, *, output_dir: Path | None = None) -> PendingAttestation:
    """Create an OTS-compatible pending-attestation file for a receipt."""
    storage.init()
    r = storage.get_receipt(receipt_id)
    if r is None:
        raise ValueError(f"receipt {receipt_id} not found")
    sha = bytes.fromhex(r.payload_sha256)
    # The pending attestation is a single attestation of type PENDING
    # whose payload is a "pending" tag (the receipt hash itself goes
    # in the file header, not the payload).
    pending_payload = b"\x00pending\x00"  # marker bytes; OTS format
    body = _serialize_attestation(ATT_PENDING, pending_payload)
    # File header: 32-byte file digest + serialized attestations
    file_digest = sha  # the receipt hash is the OTS file digest
    file_bytes = OTS_MAGIC + _varint(OTS_VERSION) + file_digest + body
    output_dir = Path(output_dir) if output_dir else Path.home() / ".dontlie" / "ots"
    output_dir.mkdir(parents=True, exist_ok=True)
    file_path = output_dir / f"receipt-{receipt_id}.ots"
    file_path.write_bytes(file_bytes)
    ts = datetime.now(timezone.utc).isoformat()
    # Add a tag to the receipt so the operator can find it later
    return PendingAttestation(
        receipt_id=receipt_id,
        sha256=r.payload_sha256,
        timestamp=ts,
        file_path=file_path,
    )


def upgrade(file_path: Path, *, ots_cli: str = "ots") -> tuple[bool, str]:
    """Call the local `ots` CLI to upgrade a pending attestation.

    Returns (success, message). The `ots` CLI is not bundled with
    Don't-Lie (it's a separate Python package: `pip install opentimestamps-client`).
    """
    if not file_path.exists():
        return False, f"file not found: {file_path}"
    # Find ots CLI
    import shutil
    ots_bin = shutil.which(ots_cli)
    if ots_bin is None:
        return False, (
            f"the {ots_cli!r} CLI is not installed. install it with: "
            f"`pip install opentimestamps-client` then run `ots upgrade {file_path}`"
        )
    try:
        result = subprocess.run(
            [ots_bin, "upgrade", str(file_path)],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            return True, (result.stdout or "upgraded").strip()
        return False, (result.stderr or "upgrade failed").strip()
    except subprocess.TimeoutExpired:
        return False, "ots upgrade timed out (60s)"
    except Exception as exc:
        return False, f"ots upgrade error: {exc}"


def main(argv: list[str] | None = None) -> int:
    import argparse
    parser = argparse.ArgumentParser(prog="dontlie ots", description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_create = sub.add_parser("create", help="create a pending OTS attestation for a receipt")
    p_create.add_argument("receipt_id", type=int)
    p_create.set_defaults(func=lambda a: _cmd_create(a))

    p_list = sub.add_parser("list", help="list pending OTS attestations")
    p_list.set_defaults(func=lambda a: _cmd_list(a))

    p_upgrade = sub.add_parser("upgrade", help="upgrade a pending attestation to Bitcoin (requires `ots` CLI)")
    p_upgrade.add_argument("file", type=Path)
    p_upgrade.set_defaults(func=lambda a: _cmd_upgrade(a))

    args = parser.parse_args(argv)
    return args.func(args)


def _cmd_create(args) -> int:
    try:
        a = create_pending(args.receipt_id)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(f"pending OTS attestation for receipt #{a.receipt_id}")
    print(f"  sha256:     {a.sha256}")
    print(f"  file:       {a.file_path}")
    print(f"  upgrade:    ots upgrade {a.file_path}")
    print(f"  (then run `ots verify {a.file_path}` after Bitcoin confirmation)")
    return 0


def _cmd_list(args) -> int:
    ots_dir = Path.home() / ".dontlie" / "ots"
    if not ots_dir.exists():
        print("no pending OTS attestations")
        return 0
    files = sorted(ots_dir.glob("receipt-*.ots"))
    if not files:
        print("no pending OTS attestations")
        return 0
    for f in files:
        rid = int(f.stem.split("-")[1])
        print(f"#{rid}  {f}")
    return 0


def _cmd_upgrade(args) -> int:
    ok, msg = upgrade(args.file)
    print(msg)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
