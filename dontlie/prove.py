"""Build a portable, independently checkable evidence packet."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import __version__, storage
from .demo import render_report

BUNDLE_NAME = "receipts.bundle.json"
REPORT_NAME = "receipt-report.html"
MANIFEST_NAME = "manifest.json"
CHECKSUMS_NAME = "SHA256SUMS"
VERIFY_NAME = "VERIFY.txt"
PACKET_FORMAT = "dontlie-evidence-packet"
PACKET_VERSION = 1


class ProveError(RuntimeError):
    """Raised when a safe evidence packet cannot be produced."""


@dataclass(frozen=True)
class PacketResult:
    """Summary of a successfully published evidence packet."""

    output_dir: Path
    receipt_count: int


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _preflight_output(output_dir: Path) -> None:
    if output_dir.is_symlink():
        raise ProveError(f"refusing symlink output directory: {output_dir}")
    if output_dir.exists():
        if not output_dir.is_dir():
            raise ProveError(f"output path already exists and is not a directory: {output_dir}")
        if any(output_dir.iterdir()):
            raise ProveError(f"output directory is not empty: {output_dir}")


def _manifest(
    receipt_count: int,
    bundle_sha256: str,
    report_sha256: str,
) -> dict[str, object]:
    return {
        "format": PACKET_FORMAT,
        "version": PACKET_VERSION,
        "dontlie_version": __version__,
        "receipt_count": receipt_count,
        "integrity": {
            "result": "verified",
            "valid_receipts": receipt_count,
            "invalid_receipts": 0,
        },
        "artifacts": {
            BUNDLE_NAME: {"sha256": bundle_sha256},
            REPORT_NAME: {"sha256": report_sha256},
        },
        "claims": {
            "chain_integrity": "verified",
            "signer_identity": "requires external key pinning",
            "provider_identity": "recorded, not independently attested",
            "answer_truth": "not evaluated",
        },
    }


def _verification_text() -> str:
    release_url = (
        "https://github.com/Matrix-ops77/dont-lie/releases/download/"
        f"v{__version__}/dontlie-{__version__}-py3-none-any.whl"
    )
    return f"""Don't-Lie evidence packet verification
========================================

Run these commands from inside this packet directory.

1. Check that the portable bundle and HTML report match the packet hashes:

   shasum -a 256 -c SHA256SUMS

2. Verify every receipt, signature, payload hash, and parent link locally:

   dontlie verify --export {BUNDLE_NAME} --verbose

   From a Don't-Lie source checkout, the equivalent command is:

   python -m dontlie verify --export {BUNDLE_NAME} --verbose

3. Optionally reproduce the self-contained HTML report:

   python -m dontlie.demo.render_report {BUNDLE_NAME} receipt-report.reproduced.html

If Don't-Lie {__version__} is not installed and network access is allowed,
install the version-matched wheel directly from the current GitHub release:

   python -m venv .dontlie-verify
   . .dontlie-verify/bin/activate
   python -m pip install {release_url}
   dontlie verify --export {BUNDLE_NAME} --verbose

Trust boundary
--------------

Successful verification establishes chain integrity for the receipt bytes in
this packet. Signer identity requires pinning each key ID to public-key material
obtained through an external trusted channel:

   dontlie verify --export {BUNDLE_NAME} --public-key KEY_ID=/trusted/key.pem --verbose

Provider identity is recorded in the receipts, not independently attested.
The truth or correctness of model answers is not evaluated.
"""


def build_packet(output_dir: Path, *, title: str = "Don't-Lie receipt report") -> PacketResult:
    """Verify the local vault and atomically publish one evidence packet."""
    _preflight_output(output_dir)
    storage.init()
    source_report = storage.verify_chain_report()
    receipt_count = source_report.ok_count + source_report.bad_count
    if receipt_count == 0:
        raise ProveError("cannot prove an empty receipt vault")
    if not source_report.valid:
        raise ProveError(
            "source receipt chain is invalid "
            f"({source_report.ok_count} ok, {source_report.bad_count} bad)"
        )

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging_dir = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name or 'dontlie-packet'}.staging-",
            dir=output_dir.parent,
        )
    )
    published = False
    try:
        bundle = staging_dir / BUNDLE_NAME
        report = staging_dir / REPORT_NAME
        exported_count = storage.export_bundle(bundle)
        if exported_count != receipt_count:
            raise ProveError(
                "exported receipt count changed during packet creation "
                f"({exported_count} != {receipt_count})"
            )

        export_report = storage.verify_export(bundle)
        if not export_report.valid or export_report.ok_count != receipt_count:
            raise ProveError(
                "exported bundle failed verification "
                f"({export_report.ok_count} ok, {export_report.bad_count} bad)"
            )

        report.write_text(
            render_report.render(bundle, title=title, packet=True),
            encoding="utf-8",
        )
        bundle_sha256 = _sha256(bundle)
        report_sha256 = _sha256(report)

        manifest = _manifest(receipt_count, bundle_sha256, report_sha256)
        (staging_dir / MANIFEST_NAME).write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        (staging_dir / CHECKSUMS_NAME).write_text(
            f"{bundle_sha256}  {BUNDLE_NAME}\n"
            f"{report_sha256}  {REPORT_NAME}\n",
            encoding="utf-8",
        )
        (staging_dir / VERIFY_NAME).write_text(
            _verification_text(),
            encoding="utf-8",
        )

        _preflight_output(output_dir)
        if output_dir.exists():
            output_dir.rmdir()
        os.replace(staging_dir, output_dir)
        published = True
    finally:
        if not published:
            shutil.rmtree(staging_dir, ignore_errors=True)

    return PacketResult(output_dir=output_dir, receipt_count=receipt_count)
