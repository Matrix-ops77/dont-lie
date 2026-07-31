"""Tests for release artifact metadata normalization."""

from __future__ import annotations

import gzip
import io
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools import reproducible_build


class SdistNormalizationTest(unittest.TestCase):
    def _write_archive(
        self,
        path: Path,
        *,
        directory_mode: int,
        file_mode: int,
        executable_mode: int,
    ) -> None:
        with path.open("wb") as raw, gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw,
            mtime=123,
        ) as compressed, tarfile.open(
            fileobj=compressed,
            mode="w",
            format=tarfile.PAX_FORMAT,
        ) as archive:
            directory = tarfile.TarInfo("dontlie-0.0.0")
            directory.type = tarfile.DIRTYPE
            directory.mode = directory_mode
            directory.mtime = 456
            archive.addfile(directory)

            regular = tarfile.TarInfo("dontlie-0.0.0/module.py")
            regular.mode = file_mode
            regular.mtime = 456
            regular.size = len(b"pass\n")
            archive.addfile(regular, io.BytesIO(b"pass\n"))

            executable = tarfile.TarInfo("dontlie-0.0.0/run.sh")
            executable.mode = executable_mode
            executable.mtime = 456
            executable.size = len(b"#!/bin/sh\n")
            archive.addfile(executable, io.BytesIO(b"#!/bin/sh\n"))

    def test_normalizes_modes_and_ownership(self) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dontlie-sdist-normalize-"
        ) as temp:
            archive = Path(temp) / "dontlie.tar.gz"
            self._write_archive(
                archive,
                directory_mode=0o775,
                file_mode=0o664,
                executable_mode=0o775,
            )

            reproducible_build._normalize_sdist(archive, epoch=999)

            with tarfile.open(archive, "r:gz") as normalized:
                members = {member.name: member for member in normalized}

        self.assertEqual(members["dontlie-0.0.0"].mode, 0o755)
        self.assertEqual(members["dontlie-0.0.0/module.py"].mode, 0o644)
        self.assertEqual(members["dontlie-0.0.0/run.sh"].mode, 0o755)
        for member in members.values():
            self.assertEqual(member.mtime, 999)
            self.assertEqual(member.uid, 0)
            self.assertEqual(member.gid, 0)
            self.assertEqual(member.uname, "")
            self.assertEqual(member.gname, "")

    def test_archives_differing_only_in_platform_modes_become_identical(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory(
            prefix="dontlie-sdist-cross-platform-"
        ) as temp:
            macos = Path(temp) / "macos.tar.gz"
            linux = Path(temp) / "linux.tar.gz"
            self._write_archive(
                macos,
                directory_mode=0o775,
                file_mode=0o664,
                executable_mode=0o775,
            )
            self._write_archive(
                linux,
                directory_mode=0o755,
                file_mode=0o644,
                executable_mode=0o755,
            )

            reproducible_build._normalize_sdist(macos, epoch=999)
            reproducible_build._normalize_sdist(linux, epoch=999)

            self.assertEqual(macos.read_bytes(), linux.read_bytes())


if __name__ == "__main__":
    unittest.main()
