#!/usr/bin/env python3
"""Re-embed a legacy hashing profile into a new local Qwen3 profile."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from echo_veil.agent_memory import (
    AgentMemory,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    HashingTextEmbedder,
    OllamaTextEmbedder,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rehydrate a legacy hashing profile into a fresh Qwen3 profile "
            "without creating a plaintext export."
        )
    )
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--source-profile", required=True)
    parser.add_argument("--target-profile", required=True)
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--dimension", type=int, default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument(
        "--confirm",
        action="store_true",
        help="required acknowledgement that the target must be a fresh profile",
    )
    return parser


def run(args: argparse.Namespace) -> dict[str, Any]:
    if args.confirm is not True:
        raise ValueError("migration requires --confirm")
    if args.source_profile == args.target_profile:
        raise ValueError("source and target profiles must be different")
    semantic = OllamaTextEmbedder(
        model=args.model,
        base_url=args.ollama_url,
        dimension=args.dimension,
    )
    with AgentMemory(
        args.state_dir,
        profile=args.source_profile,
        embed=HashingTextEmbedder(),
    ) as source:
        with AgentMemory(
            args.state_dir,
            profile=args.target_profile,
            embed=semantic,
        ) as target:
            return source.migrate_to(target, confirm=True)


def main(argv: list[str] | None = None) -> int:
    try:
        report = run(build_parser().parse_args(argv))
    except Exception as exc:
        print(json.dumps({"error": type(exc).__name__, "message": str(exc)}))
        return 1
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
