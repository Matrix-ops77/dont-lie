"""Build byte-reproducible wheel and source archives.

The wheel builder honors ``SOURCE_DATE_EPOCH``. Setuptools' source archive
still carries per-build tar metadata, so this script normalizes that metadata
before comparing two independent builds and publishing either artifact.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import io
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

ARTIFACT_SUFFIXES = (".whl", ".tar.gz")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as artifact:
        for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _source_date_epoch() -> int:
    configured = os.environ.get("SOURCE_DATE_EPOCH")
    if configured is not None:
        return int(configured)
    completed = subprocess.run(
        ["git", "log", "-1", "--pretty=%ct"],
        check=True,
        capture_output=True,
        text=True,
    )
    return int(completed.stdout.strip())


def _normalize_sdist(path: Path, epoch: int) -> None:
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for member in source.getmembers():
            payload = None
            if member.isfile():
                extracted = source.extractfile(member)
                if extracted is None:
                    raise RuntimeError(f"could not read {member.name} from {path}")
                payload = extracted.read()
            entries.append((copy.copy(member), payload))

    temporary = path.with_suffix(path.suffix + ".normalized")
    with temporary.open("wb") as raw, gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=raw,
        mtime=epoch,
    ) as compressed, tarfile.open(
        fileobj=compressed,
        mode="w",
        format=tarfile.PAX_FORMAT,
    ) as target:
        for member, payload in entries:
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            target.addfile(
                member,
                io.BytesIO(payload) if payload is not None else None,
            )
    temporary.replace(path)


def _artifacts(directory: Path) -> dict[str, Path]:
    result = {
        path.name: path
        for path in directory.iterdir()
        if any(path.name.endswith(suffix) for suffix in ARTIFACT_SUFFIXES)
    }
    if len(result) != 2:
        raise RuntimeError(f"expected one wheel and one sdist in {directory}")
    return result


def _build_once(directory: Path, epoch: int) -> dict[str, Path]:
    environment = os.environ.copy()
    environment["SOURCE_DATE_EPOCH"] = str(epoch)
    subprocess.run(
        [sys.executable, "-m", "build", "--outdir", str(directory)],
        check=True,
        env=environment,
    )
    artifacts = _artifacts(directory)
    sdist = next(path for name, path in artifacts.items() if name.endswith(".tar.gz"))
    _normalize_sdist(sdist, epoch)
    return artifacts


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: python tools/reproducible_build.py OUTPUT_DIR", file=sys.stderr)
        return 2

    output = Path(sys.argv[1]).resolve()
    if output.exists() and any(output.iterdir()):
        print(f"output directory is not empty: {output}", file=sys.stderr)
        return 2
    output.mkdir(parents=True, exist_ok=True)

    epoch = _source_date_epoch()
    with (
        tempfile.TemporaryDirectory(prefix="dontlie-build-a-") as first_raw,
        tempfile.TemporaryDirectory(prefix="dontlie-build-b-") as second_raw,
    ):
        first = _build_once(Path(first_raw), epoch)
        second = _build_once(Path(second_raw), epoch)

        if first.keys() != second.keys():
            raise RuntimeError("independent builds produced different artifact names")

        for name in sorted(first):
            first_hash = _sha256(first[name])
            second_hash = _sha256(second[name])
            if first_hash != second_hash:
                raise RuntimeError(
                    f"artifact is not reproducible: {name} "
                    f"{first_hash} != {second_hash}"
                )
            shutil.copy2(first[name], output / name)
            print(f"{first_hash}  {name}")

    print(f"reproducible build: PASS (SOURCE_DATE_EPOCH={epoch})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
