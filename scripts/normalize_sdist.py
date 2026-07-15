#!/usr/bin/env python3
"""Normalize a Python sdist tarball for byte-for-byte reproducibility."""

from __future__ import annotations

import argparse
import copy
import gzip
import os
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path, PurePosixPath


def normalize_sdist(path: Path, epoch: int) -> None:
    path = path.resolve()
    entries: list[tuple[tarfile.TarInfo, bytes | None]] = []
    with tarfile.open(path, "r:gz") as source:
        for original in source.getmembers():
            member_path = PurePosixPath(original.name)
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"unsafe archive path: {original.name}")
            if original.issym() or original.islnk():
                raise ValueError(f"archive links are prohibited: {original.name}")
            payload: bytes | None = None
            if original.isfile():
                extracted = source.extractfile(original)
                if extracted is None:
                    raise ValueError(f"cannot read archive member: {original.name}")
                payload = extracted.read()
            member = copy.copy(original)
            member.mtime = epoch
            member.uid = 0
            member.gid = 0
            member.uname = ""
            member.gname = ""
            member.pax_headers = {}
            member.mode = 0o755 if member.isdir() or original.mode & 0o111 else 0o644
            entries.append((member, payload))

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, delete=False) as temporary:
            temporary_name = temporary.name
            with gzip.GzipFile(
                filename="",
                mode="wb",
                fileobj=temporary,
                compresslevel=9,
                mtime=epoch,
            ) as compressed:
                with tarfile.open(
                    fileobj=compressed,
                    mode="w",
                    format=tarfile.PAX_FORMAT,
                ) as destination:
                    for member, payload in sorted(
                        entries, key=lambda item: item[0].name
                    ):
                        if payload is None:
                            destination.addfile(member)
                        else:
                            destination.addfile(member, BytesIO(payload))
        assert temporary_name is not None
        os.replace(temporary_name, path)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", nargs="+", type=Path)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    args = parser.parse_args()
    if args.epoch <= 0:
        parser.error("a positive --epoch or SOURCE_DATE_EPOCH is required")
    for archive in args.archive:
        normalize_sdist(archive, args.epoch)
        print(f"Normalized {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
