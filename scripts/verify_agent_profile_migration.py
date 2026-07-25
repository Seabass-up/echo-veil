#!/usr/bin/env python3
"""Verify an existing Echo Veil profile migration without exporting plaintext."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from echo_veil.migration import verify_profile_migration


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--source-profile", required=True)
    parser.add_argument("--target-profile", required=True)
    parser.add_argument("--source-scope", default="local-user")
    parser.add_argument("--target-scope", default="local-user")
    parser.add_argument(
        "--allow-target-extras",
        action="store_true",
        help="allow unrelated target records while still requiring every source record",
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    return verify_profile_migration(
        args.state_dir,
        source_profile=args.source_profile,
        target_profile=args.target_profile,
        source_scope=args.source_scope,
        target_scope=args.target_scope,
        allow_target_extras=args.allow_target_extras,
    )


def main(argv: list[str] | None = None) -> int:
    try:
        report = run(build_parser().parse_args(argv))
    except Exception as exc:
        print(
            json.dumps(
                {
                    "error": type(exc).__name__,
                    "message": "profile migration verification failed",
                }
            )
        )
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
