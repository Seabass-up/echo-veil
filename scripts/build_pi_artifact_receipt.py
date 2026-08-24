#!/usr/bin/env python3
"""Build or verify the exact receipt for the reviewed Pi integration bytes."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from typing import Any

from echo_veil._json import strict_json_loads
from echo_veil.guarded_runner import (
    PI_ARTIFACT_FILES,
    PI_ARTIFACT_SCHEMA,
    PI_HOST_VERSION,
    PI_PACKAGE_VERSION,
    _read_pi_artifact_file,
)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_DIRECTORY = ROOT / "integrations" / "pi"


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _safe_directory(path: Path) -> Path:
    candidate = path.expanduser().absolute()
    if candidate.is_symlink():
        raise ValueError("Pi artifact directory must not be a symlink")
    root = candidate.resolve(strict=True)
    details = root.stat()
    getuid = getattr(os, "getuid", None)
    if (
        not stat.S_ISDIR(details.st_mode)
        or details.st_mode & 0o022
        or (callable(getuid) and details.st_uid != getuid())
    ):
        raise ValueError("Pi artifact directory is unsafe")
    return root


def build_receipt(path: Path) -> dict[str, Any]:
    root = _safe_directory(path)
    files = {
        name: "sha256:"
        + hashlib.sha256(_read_pi_artifact_file(root / name)).hexdigest()
        for name in PI_ARTIFACT_FILES
    }
    unsigned = {
        "files": files,
        "host": "pi",
        "host_version": PI_HOST_VERSION,
        "package": "pi-extension-echo-veil",
        "package_version": PI_PACKAGE_VERSION,
        "schema": PI_ARTIFACT_SCHEMA,
    }
    return {
        "artifact_authority_id": "sha256:"
        + hashlib.sha256(_canonical_json(unsigned)).hexdigest(),
        **unsigned,
    }


def _write_atomic(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, indent=2, sort_keys=True).encode("ascii") + b"\n"
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as stream:
            descriptor = -1
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary.exists():
            temporary.unlink()


def run(path: Path, *, check: bool) -> dict[str, Any]:
    root = _safe_directory(path)
    expected = build_receipt(root)
    receipt_path = root / "artifact-receipt.json"
    if check:
        existing = strict_json_loads(_read_pi_artifact_file(receipt_path))
        if existing != expected:
            raise RuntimeError("Pi artifact receipt does not match reviewed bytes")
    else:
        _write_atomic(receipt_path, expected)
    return {
        "artifact_authority_id": expected["artifact_authority_id"],
        "files_verified": len(PI_ARTIFACT_FILES),
        "host_version": PI_HOST_VERSION,
        "package_version": PI_PACKAGE_VERSION,
        "schema": PI_ARTIFACT_SCHEMA,
        "status": "verified" if check else "written",
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=DEFAULT_DIRECTORY)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    try:
        report = run(args.directory, check=args.check)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": "Pi artifact receipt verification failed",
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
