#!/usr/bin/env python3
"""Migrate one compatible agent profile into a fresh scoped Qwen3 profile."""

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
    TextEmbedder,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Rehydrate a compatible legacy or scoped agent profile into a fresh "
            "scoped Qwen3 profile without creating a plaintext export."
        )
    )
    parser.add_argument("--state-dir", type=Path)
    parser.add_argument("--source-profile", required=True)
    parser.add_argument("--target-profile", required=True)
    parser.add_argument("--source-scope", default="local-user")
    parser.add_argument("--target-scope", default="local-user")
    parser.add_argument(
        "--source-embedder",
        choices=("hashing", "ollama"),
        default="ollama",
        help="embedding identity already bound to the source profile",
    )
    parser.add_argument("--source-model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--source-dimension",
        type=int,
        default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    )
    parser.add_argument("--target-model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--target-dimension",
        type=int,
        default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
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

    source_embedder = _source_embedder(args)
    target_embedder = OllamaTextEmbedder(
        model=args.target_model,
        base_url=args.ollama_url,
        dimension=args.target_dimension,
    )
    with AgentMemory(
        args.state_dir,
        profile=args.source_profile,
        scope=args.source_scope,
        embed=source_embedder,
    ) as source:
        with AgentMemory(
            args.state_dir,
            profile=args.target_profile,
            scope=args.target_scope,
            embed=target_embedder,
        ) as target:
            report = source.migrate_to(target, confirm=True)
            target_report = target.doctor()

    report["target_security_schema"] = target_report["security_schema"]
    report["target_all_records_shielded"] = target_report["memory_layers"][
        "all_records_shielded"
    ]
    return report


def _source_embedder(args: argparse.Namespace) -> TextEmbedder:
    if args.source_embedder == "hashing":
        return HashingTextEmbedder()
    return OllamaTextEmbedder(
        model=args.source_model,
        base_url=args.ollama_url,
        dimension=args.source_dimension,
    )


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
