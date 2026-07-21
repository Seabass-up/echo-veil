#!/usr/bin/env python3
"""Run a small keyword, paraphrase, and distractor recall qualification."""

from __future__ import annotations

import argparse
import json
import statistics
import tempfile
import time
from pathlib import Path
from typing import Any

from echo_veil.agent_memory import (
    AgentMemory,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    OllamaTextEmbedder,
)

MEMORIES = (
    (
        "Harbor project labor rate",
        "Employee labor on the Harbor project is priced at 137 dollars per hour.",
    ),
    (
        "Canonical project folder",
        "Current company project documents belong in the canonical Shared Drive folder.",
    ),
    (
        "Taylor family",
        "Taylor's children are Avery, Morgan, and Riley.",
    ),
    (
        "Messaging boundary",
        "The messaging integration is read-only; never send, reply, or react.",
    ),
    (
        "Power supply reference",
        "The approved power supply reference is the Mean Well HDR series.",
    ),
)

CASES = (
    (
        "keyword",
        "Harbor project labor rate 137 dollars per hour",
        "Harbor project labor rate",
    ),
    (
        "paraphrase",
        "What hourly amount should employee work be priced at?",
        "Harbor project labor rate",
    ),
    (
        "keyword",
        "canonical project documents Shared Drive folder",
        "Canonical project folder",
    ),
    (
        "paraphrase",
        "Where should current company project documents live?",
        "Canonical project folder",
    ),
    ("keyword", "Taylor family children Avery Morgan Riley", "Taylor family"),
    ("paraphrase", "Who are the kids in Taylor's family?", "Taylor family"),
    (
        "keyword",
        "messaging read-only never send reply react",
        "Messaging boundary",
    ),
    (
        "paraphrase",
        "Am I allowed to write back to someone through messaging?",
        "Messaging boundary",
    ),
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--dimension", type=int, default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    embedder = OllamaTextEmbedder(
        model=args.model,
        dimension=args.dimension,
        base_url=args.ollama_url,
    )
    remember_ms: list[float] = []
    recall_ms: list[float] = []
    results: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="echo-veil-semantic-") as directory:
        with AgentMemory(
            Path(directory),
            profile="benchmark",
            capacity=20,
            embed=embedder,
        ) as memory:
            for topic, payload in MEMORIES:
                started = time.perf_counter()
                memory.remember(topic, payload)
                remember_ms.append((time.perf_counter() - started) * 1000.0)

            for kind, query, expected_topic in CASES:
                started = time.perf_counter()
                response = memory.recall(query, top_k=1)
                recall_ms.append((time.perf_counter() - started) * 1000.0)
                top = response["results"][0] if response["results"] else None
                results.append(
                    {
                        "kind": kind,
                        "expected": expected_topic,
                        "actual": None if top is None else top["topic"],
                        "score": None if top is None else top["score"],
                        "passed": top is not None and top["topic"] == expected_topic,
                    }
                )

            started = time.perf_counter()
            distractor = memory.recall("purple llama tungsten", top_k=1)
            recall_ms.append((time.perf_counter() - started) * 1000.0)

    keyword = [item for item in results if item["kind"] == "keyword"]
    paraphrase = [item for item in results if item["kind"] == "paraphrase"]
    report = {
        "model": embedder.model,
        "dimension": embedder.dimension,
        "default_min_score": embedder.default_min_score,
        "keyword": f"{sum(bool(item['passed']) for item in keyword)}/{len(keyword)}",
        "paraphrase": (
            f"{sum(bool(item['passed']) for item in paraphrase)}/{len(paraphrase)}"
        ),
        "distractor_rejected": not distractor["results"],
        "mean_remember_ms": round(statistics.mean(remember_ms), 2),
        "mean_recall_ms": round(statistics.mean(recall_ms), 2),
        "cases": results,
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return (
        0
        if all(item["passed"] for item in results) and not distractor["results"]
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
