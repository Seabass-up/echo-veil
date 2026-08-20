#!/usr/bin/env python3
"""Prove that the pinned v0.7 core fails closed on an activated v3 profile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys
import tempfile

from echo_veil.agent_memory import AgentMemory


LEGACY_VERSION = "0.7.0"
_LEGACY_PROBE = """
from echo_veil.agent_memory import AgentMemory
import os
with AgentMemory(os.environ["ECHO_VEIL_DOWNGRADE_STATE_DIR"]) as memory:
    memory.doctor()
print("legacy-opened")
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--legacy-source",
        type=Path,
        required=True,
        help="immutable checkout of the pinned v0.7.0 source",
    )
    return parser


def _project_version(source: Path) -> str:
    project = source / "pyproject.toml"
    if not project.is_file():
        raise ValueError("legacy source does not contain pyproject.toml")
    for line in project.read_text(encoding="utf-8").splitlines():
        if line.startswith("version = "):
            return line.split('"', 2)[1]
    raise ValueError("legacy source version is unavailable")


def run(legacy_source: Path) -> dict[str, object]:
    source = legacy_source.resolve(strict=True)
    if _project_version(source) != LEGACY_VERSION:
        raise ValueError("legacy source is not the required v0.7.0 release")
    package = source / "src" / "echo_veil"
    if not package.is_dir():
        raise ValueError("legacy Echo Veil package is unavailable")

    private_tmp = Path("/private/tmp" if sys.platform == "darwin" else "/tmp")
    with tempfile.TemporaryDirectory(
        prefix="echo-veil-envelope-compat-",
        dir=private_tmp,
    ) as temporary:
        state_dir = Path(temporary) / "state"
        with AgentMemory(state_dir) as memory:
            memory.remember(
                "downgrade barrier",
                "The activated profile must not open through a v0.7 core.",
                provenance=["qualification:cross-version"],
            )
            result = memory.migrate_record_envelope_v3(
                confirm=True,
                batch_size=100,
            )
            if result["state"] != "verified":
                raise RuntimeError("record-envelope v3 qualification did not converge")

        environment = {
            "ECHO_VEIL_DOWNGRADE_STATE_DIR": str(state_dir),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONPATH": str(source / "src"),
        }
        completed = subprocess.run(  # noqa: S603 -- fixed interpreter/probe
            [sys.executable, "-c", _LEGACY_PROBE],
            cwd=source,
            env=environment,
            capture_output=True,
            check=False,
            text=True,
            timeout=30,
        )
        if completed.returncode == 0 or "legacy-opened" in completed.stdout:
            raise RuntimeError("v0.7 core did not honor the v3 downgrade barrier")

    return {
        "legacy_core": LEGACY_VERSION,
        "legacy_open_blocked": True,
        "preflight_protocol": "preflight_v2",
        "record_envelope": "v3",
        "schema": "echo-veil-record-envelope-downgrade-check-v1",
    }


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        report = run(args.legacy_source)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": "record-envelope downgrade verification failed",
                },
                sort_keys=True,
            )
        )
        return 1
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
