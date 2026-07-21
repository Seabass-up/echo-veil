#!/usr/bin/env python3
"""Run Echo Veil's held-out local retrieval quality gate."""

from __future__ import annotations

import argparse
import json
import math
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

from echo_veil.agent_memory import (
    AgentMemory,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    OllamaTextEmbedder,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "benchmarks" / "agent_memory_quality.json"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--dimension", type=int, default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    return parser


def _load_cases(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("quality benchmark must contain a JSON object")
    for key in ("memories", "queries", "distractors"):
        if not isinstance(data.get(key), list) or not data[key]:
            raise ValueError(f"quality benchmark {key} must be a non-empty list")
    return data


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cases = _load_cases(args.cases)
    resolution_started = time.perf_counter()
    embedder = OllamaTextEmbedder(
        model=args.model,
        dimension=args.dimension,
        base_url=args.ollama_url,
    )
    model_resolution_ms = (time.perf_counter() - resolution_started) * 1000.0
    ids: dict[str, str] = {}
    remember_ms: list[float] = []
    recall_ms: list[float] = []
    outcomes: list[dict[str, Any]] = []

    with tempfile.TemporaryDirectory(prefix="echo-veil-quality-") as directory:
        state_dir = Path(directory)
        with AgentMemory(
            state_dir,
            profile="quality-qwen3",
            capacity=100,
            embed=embedder,
        ) as memory:
            for item in cases["memories"]:
                supersedes = [ids[value] for value in item.get("supersedes", [])]
                started = time.perf_counter()
                result = memory.remember(
                    item["topic"],
                    item["payload"],
                    effective_at=float(item["effective_at"]),
                    supersedes=supersedes,
                )
                remember_ms.append((time.perf_counter() - started) * 1000.0)
                ids[item["id"]] = str(result["vine_id"])

        restart_started = time.perf_counter()
        with AgentMemory(
            state_dir,
            profile="quality-qwen3",
            capacity=100,
            embed=embedder,
        ) as memory:
            restart_ms = (time.perf_counter() - restart_started) * 1000.0
            doctor = memory.doctor()
            for item in cases["queries"]:
                started = time.perf_counter()
                response = memory.recall(
                    item["query"],
                    top_k=1,
                    as_of=(None if item.get("as_of") is None else float(item["as_of"])),
                )
                elapsed = (time.perf_counter() - started) * 1000.0
                recall_ms.append(elapsed)
                top = response["results"][0] if response["results"] else None
                expected = ids[item["expected"]]
                outcomes.append(
                    {
                        "category": item["category"],
                        "expected": item["expected"],
                        "actual_topic": None if top is None else top["topic"],
                        "score": None if top is None else top["score"],
                        "passed": top is not None and top["vine_id"] == expected,
                    }
                )

            distractor_passes = 0
            for query in cases["distractors"]:
                started = time.perf_counter()
                response = memory.recall(query, top_k=1)
                recall_ms.append((time.perf_counter() - started) * 1000.0)
                distractor_passes += int(not response["results"])

    category_counts: dict[str, list[bool]] = defaultdict(list)
    for outcome in outcomes:
        category_counts[str(outcome["category"])].append(bool(outcome["passed"]))
    categories = {
        category: {
            "passed": sum(values),
            "total": len(values),
            "rate": round(sum(values) / len(values), 4),
        }
        for category, values in sorted(category_counts.items())
    }
    all_queries_passed = all(bool(item["passed"]) for item in outcomes)
    all_distractors_passed = distractor_passes == len(cases["distractors"])
    retrieval_index = doctor["retrieval"]
    report = {
        "verdict": (
            "pass" if all_queries_passed and all_distractors_passed else "fail"
        ),
        "model": embedder.model,
        "dimension": embedder.dimension,
        "memory_count": len(cases["memories"]),
        "query_count": len(outcomes),
        "categories": categories,
        "distractor_rejection": {
            "passed": distractor_passes,
            "total": len(cases["distractors"]),
        },
        "model_resolution_ms": round(model_resolution_ms, 2),
        "first_remember_ms": round(remember_ms[0], 2),
        "steady_mean_remember_ms": round(
            sum(remember_ms[1:]) / len(remember_ms[1:]), 2
        ),
        "restart_ms": round(restart_ms, 2),
        "mean_remember_ms": round(sum(remember_ms) / len(remember_ms), 2),
        "mean_recall_ms": round(sum(recall_ms) / len(recall_ms), 2),
        "p95_recall_ms": round(_percentile(recall_ms, 0.95), 2),
        "unindexed_payload_count": retrieval_index["unindexed_payload_count"],
        "failures": [item for item in outcomes if not item["passed"]],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
