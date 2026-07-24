#!/usr/bin/env python3
"""Run the held-out Echo Veil cases against an isolated OpenClaw memory-core agent."""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "benchmarks" / "agent_memory_quality.json"
MAX_COMMAND_SECONDS = 180


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cases", type=Path, default=DEFAULT_CASES)
    parser.add_argument("--openclaw", default="openclaw")
    return parser


def _run(command: list[str], *, timeout: int = MAX_COMMAND_SECONDS) -> str:
    result = subprocess.run(  # noqa: S603 - fixed argv, no shell
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"OpenClaw benchmark command failed with status {result.returncode}"
        )
    return result.stdout


def _load_cases(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("quality benchmark must contain a JSON object")
    return data


def _write_corpus(workspace: Path, cases: dict[str, Any]) -> None:
    memory_dir = workspace / "memory"
    memory_dir.mkdir(parents=True, mode=0o700)
    for item in cases["memories"]:
        supersedes = ", ".join(item.get("supersedes", [])) or "none"
        text = (
            f"# {item['topic']}\n\n"
            f"Benchmark record: {item['id']}\n"
            f"Effective at: {item['effective_at']}\n"
            f"Supersedes: {supersedes}\n\n"
            f"{item['payload']}\n"
        )
        (memory_dir / f"{item['id']}.md").write_text(text, encoding="utf-8")


def _top_path(output: str) -> str | None:
    parsed = json.loads(output)
    results = parsed.get("results")
    if not isinstance(results, list) or not results:
        return None
    top = results[0]
    return str(top.get("path")) if isinstance(top, dict) else None


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    index = max(0, math.ceil(percentile * len(ordered)) - 1)
    return ordered[index]


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    cases = _load_cases(args.cases)
    agent_id = f"echo-quality-{os.getpid()}"
    outcomes: list[dict[str, Any]] = []
    latencies: list[float] = []
    distractor_passes = 0
    added = False

    with tempfile.TemporaryDirectory(prefix="echo-memory-core-") as directory:
        root = Path(directory)
        workspace = root / "workspace"
        agent_dir = root / "agent"
        workspace.mkdir(mode=0o700)
        agent_dir.mkdir(mode=0o700)
        _write_corpus(workspace, cases)
        try:
            _run(
                [
                    args.openclaw,
                    "agents",
                    "add",
                    agent_id,
                    "--workspace",
                    str(workspace),
                    "--agent-dir",
                    str(agent_dir),
                    "--non-interactive",
                    "--json",
                ]
            )
            added = True
            _run(
                [
                    args.openclaw,
                    "memory",
                    "index",
                    "--agent",
                    agent_id,
                    "--force",
                ]
            )
            for item in cases["queries"]:
                started = time.perf_counter()
                output = _run(
                    [
                        args.openclaw,
                        "memory",
                        "search",
                        "--agent",
                        agent_id,
                        "--query",
                        item["query"],
                        "--max-results",
                        "1",
                        "--json",
                    ]
                )
                latencies.append((time.perf_counter() - started) * 1000.0)
                expected_path = f"memory/{item['expected']}.md"
                actual_path = _top_path(output)
                outcomes.append(
                    {
                        "category": item["category"],
                        "expected": item["expected"],
                        "actual_path": actual_path,
                        "passed": actual_path == expected_path,
                    }
                )
            for query in cases["distractors"]:
                started = time.perf_counter()
                output = _run(
                    [
                        args.openclaw,
                        "memory",
                        "search",
                        "--agent",
                        agent_id,
                        "--query",
                        query,
                        "--max-results",
                        "1",
                        "--json",
                    ]
                )
                latencies.append((time.perf_counter() - started) * 1000.0)
                distractor_passes += int(_top_path(output) is None)
        finally:
            if added:
                _run(
                    [
                        args.openclaw,
                        "agents",
                        "delete",
                        agent_id,
                        "--force",
                        "--json",
                    ]
                )

    category_counts: dict[str, list[bool]] = defaultdict(list)
    for outcome in outcomes:
        category_counts[str(outcome["category"])].append(bool(outcome["passed"]))
    report = {
        "system": "openclaw-memory-core",
        "query_count": len(outcomes),
        "categories": {
            category: {
                "passed": sum(values),
                "total": len(values),
                "rate": round(sum(values) / len(values), 4),
            }
            for category, values in sorted(category_counts.items())
        },
        "distractor_rejection": {
            "passed": distractor_passes,
            "total": len(cases["distractors"]),
        },
        "mean_search_ms": round(sum(latencies) / len(latencies), 2),
        "p95_search_ms": round(_percentile(latencies, 0.95), 2),
        "failures": [item for item in outcomes if not item["passed"]],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
