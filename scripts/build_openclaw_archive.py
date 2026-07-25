#!/usr/bin/env python3
"""Build the allowlisted OpenClaw plugin archive reproducibly."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any


EXPECTED_NAME = "openclaw-plugin-echo-veil"
EXPECTED_FILES = ["dist", "openclaw.plugin.json", "README.md"]
ARCHIVE_FILES = (
    "README.md",
    "dist/index.d.ts",
    "dist/index.js",
    "openclaw.plugin.json",
    "package.json",
)
VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[a-z]+[0-9]+)?$")
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_ARCHIVE_PAYLOAD_BYTES = 32 * 1024 * 1024


class ArchiveError(ValueError):
    """The plugin source cannot produce a trusted release archive."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ArchiveError(f"duplicate package metadata key: {key}")
        output[key] = value
    return output


def _source_file(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ArchiveError(f"unsafe plugin source path: {relative}")
    candidate = root
    for part in pure.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ArchiveError(f"plugin source must not contain links: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ArchiveError(f"plugin source is missing: {relative}") from exc
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ArchiveError(f"plugin source escapes its root: {relative}") from exc
    if not resolved.is_file():
        raise ArchiveError(f"plugin source is not a regular file: {relative}")
    return resolved


def _read_payload(path: Path, relative: str) -> bytes:
    size = path.stat().st_size
    if size > MAX_FILE_BYTES:
        raise ArchiveError(f"plugin source exceeds its size limit: {relative}")
    payload = path.read_bytes()
    if len(payload) != size:
        raise ArchiveError(f"plugin source changed while reading: {relative}")
    return payload


def _load_metadata(root: Path) -> dict[str, Any]:
    package_path = _source_file(root, "package.json")
    raw = _read_payload(package_path, "package.json")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ArchiveError("package metadata is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ArchiveError("package metadata must be an object")
    if value.get("name") != EXPECTED_NAME:
        raise ArchiveError("package name is not the reviewed OpenClaw plugin")
    version = value.get("version")
    if not isinstance(version, str) or VERSION.fullmatch(version) is None:
        raise ArchiveError("package version is not release-shaped")
    if value.get("files") != EXPECTED_FILES:
        raise ArchiveError("package files must match the reviewed release allowlist")
    return value


def build_archive(root: Path, output_dir: Path, epoch: int) -> Path:
    """Create one deterministic archive and return its absolute path."""

    if epoch <= 0:
        raise ArchiveError("source date epoch must be positive")
    root = root.expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ArchiveError("plugin root must be a directory")
    metadata = _load_metadata(root)

    payloads: list[tuple[str, bytes]] = []
    total = 0
    for relative in ARCHIVE_FILES:
        payload = _read_payload(_source_file(root, relative), relative)
        total += len(payload)
        if total > MAX_ARCHIVE_PAYLOAD_BYTES:
            raise ArchiveError("plugin archive payload exceeds its size limit")
        payloads.append((relative, payload))

    output_dir = output_dir.expanduser()
    output_dir.mkdir(parents=True, exist_ok=True)
    output_dir = output_dir.resolve(strict=True)
    if not output_dir.is_dir():
        raise ArchiveError("archive output must be a directory")
    destination = output_dir / f"{EXPECTED_NAME}-{metadata['version']}.tgz"
    if destination.is_symlink():
        raise ArchiveError("archive output must not be a symbolic link")

    temporary_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(dir=output_dir, delete=False) as temporary:
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
                ) as archive:
                    for relative, payload in sorted(payloads):
                        member = tarfile.TarInfo(f"package/{relative}")
                        member.size = len(payload)
                        member.mtime = epoch
                        member.uid = 0
                        member.gid = 0
                        member.uname = ""
                        member.gname = ""
                        member.mode = 0o644
                        member.pax_headers = {}
                        archive.addfile(member, BytesIO(payload))
        assert temporary_name is not None
        os.replace(temporary_name, destination)
        os.chmod(destination, 0o644)
        temporary_name = None
    finally:
        if temporary_name is not None:
            Path(temporary_name).unlink(missing_ok=True)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--root",
        type=Path,
        default=Path("integrations/openclaw"),
    )
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--epoch",
        type=int,
        default=int(os.environ.get("SOURCE_DATE_EPOCH", "0")),
    )
    args = parser.parse_args()
    try:
        archive = build_archive(args.root, args.output_dir, args.epoch)
    except (ArchiveError, OSError) as exc:
        parser.error(str(exc))
    print(archive)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
