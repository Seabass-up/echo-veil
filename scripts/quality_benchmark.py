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
    AlwaysAvailableMemory,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    OllamaTextEmbedder,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES = ROOT / "benchmarks" / "agent_memory_quality.json"
CONTEXT_TRACE_QUERY = "quality context trace incident escalation and backup retention"
COMPETING_MEMORY_QUERY = "quality competing deployment route quartz amber"


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
    context_remember_ms = 0.0
    context_trace_ms = 0.0
    context_semantic_passed = False
    context_availability_passed = False
    context_root_id = ""
    competing_ids: set[str] = set()
    competing_semantic_passed = False
    competing_availability_passed = False
    competing_recall_ms = 0.0
    live_refresh_ids: set[str] = set()
    live_refresh_semantic_passed = False
    live_refresh_availability_passed = False
    live_refresh_ms = 0.0

    with tempfile.TemporaryDirectory(prefix="echo-veil-quality-") as directory:
        # macOS exposes /var through a system symlink. Resolve the fresh,
        # process-owned temporary directory before applying Echo's stricter
        # no-symlink state-path policy.
        state_dir = Path(directory).resolve(strict=True)
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

            started = time.perf_counter()
            context_record = memory.remember(
                "quality context trace",
                (
                    "This benchmark logic record links incident escalation with "
                    "backup retention."
                ),
                layer="contextual_logic",
                provenance=["benchmark:quality-context"],
                promotion_reason=(
                    "The two authenticated benchmark records support this trace."
                ),
                logic_kind="causal_chain",
                related_ids=[ids["incident"], ids["backup"]],
            )
            context_remember_ms = (time.perf_counter() - started) * 1000.0
            context_root_id = str(context_record["vine_id"])
            started = time.perf_counter()
            context_response = memory.context(
                CONTEXT_TRACE_QUERY,
                max_depth=1,
                max_records=2,
            )
            context_trace_ms = (time.perf_counter() - started) * 1000.0
            context_roots = {
                str(item["vine_id"]) for item in context_response["logic_roots"]
            }
            context_evidence = {
                str(item["vine_id"]) for item in context_response["evidence"]
            }
            context_semantic_passed = (
                context_roots == {context_root_id}
                and context_evidence == {ids["incident"], ids["backup"]}
                and all(
                    item["query_scored"] is False
                    and item["layer_contract_protected"] is True
                    for item in context_response["evidence"]
                )
                and context_response["truncated"] is False
                and context_response["incomplete"] is False
                and context_response["context_contract"]["synthesis_performed"] is False
            )
            first_competing = memory.remember(
                "quality competing deployment route",
                "The benchmark deployment route is quartz.",
                provenance=["benchmark:competing-first"],
            )
            second_competing = memory.remember(
                "quality competing deployment route",
                "The benchmark deployment route is amber.",
                provenance=["benchmark:competing-second"],
            )
            competing_ids = {
                str(first_competing["vine_id"]),
                str(second_competing["vine_id"]),
            }
            started = time.perf_counter()
            competing_response = memory.recall(
                COMPETING_MEMORY_QUERY,
                top_k=1,
            )
            competing_recall_ms = (time.perf_counter() - started) * 1000.0
            competing_semantic_passed = (
                {str(item["vine_id"]) for item in competing_response["results"]}
                == competing_ids
                and competing_response["requested_top_k"] == 1
                and competing_response["effective_top_k"] == 2
                and competing_response["competing_pair_auto_expanded"] is True
                and competing_response["competing_memory_detected"] is True
                and competing_response["ranking_ambiguous"] is False
                and len(competing_response["competing_memory_groups"]) == 1
                and competing_response["competing_memory_groups"][0][
                    "protected_topic_basis"
                ]
                is True
                and competing_response["competing_memory_groups"][0][
                    "resolution_status"
                ]
                == "not_evaluated"
            )
            live_original = memory.remember(
                "quality active deployment state",
                "The quality deployment is preparing.",
                layer="live",
                provenance=["benchmark:live-start"],
                expires_at=time.time() + 600.0,
            )
            live_unchanged = memory.refresh_live(
                str(live_original["vine_id"]),
                "The quality deployment is preparing.",
                provenance=["benchmark:live-poll"],
                expires_at=time.time() + 900.0,
            )
            started = time.perf_counter()
            live_changed = memory.refresh_live(
                str(live_original["vine_id"]),
                "The quality deployment completed successfully.",
                provenance=["benchmark:live-pass"],
                expires_at=time.time() + 1_200.0,
            )
            live_refresh_ms = (time.perf_counter() - started) * 1000.0
            live_refresh_ids = {
                str(live_original["vine_id"]),
                str(live_changed["vine_id"]),
            }
            live_records = {
                str(item["vine_id"]): item for item in memory.list_memories()
            }
            live_refresh_semantic_passed = (
                live_unchanged["vine_id"] == live_original["vine_id"]
                and live_unchanged["content_changed"] is False
                and live_changed["vine_id"] != live_original["vine_id"]
                and live_changed["content_changed"] is True
                and live_changed["supersedes"] == [live_original["vine_id"]]
                and live_changed["content_policy"]["policy"]
                == "bounded-seed-crystal-v1"
                and live_changed["content_policy"]["policy_compliant"] is True
                and live_records[str(live_original["vine_id"])]["superseded_by"]
                == live_changed["vine_id"]
                and live_records[str(live_changed["vine_id"])]["superseded_by"] is None
            )
            doctor = memory.doctor()

        availability_keyword_passes = 0
        availability_keyword_total = 0
        availability_distractor_passes = 0
        availability_failures: list[dict[str, Any]] = []
        with AlwaysAvailableMemory(
            state_dir,
            profile="quality-qwen3",
            reason="quality_gate_simulated_outage",
        ) as available:
            for item in cases["queries"]:
                if item["category"] != "keyword":
                    continue
                availability_keyword_total += 1
                response = available.recall(item["query"], top_k=1)
                top = response["results"][0] if response["results"] else None
                passed = top is not None and top["vine_id"] == ids[item["expected"]]
                availability_keyword_passes += int(passed)
                if not passed:
                    availability_failures.append(
                        {
                            "query": item["query"],
                            "expected": item["expected"],
                            "actual_topic": None if top is None else top["topic"],
                            "score": None if top is None else top["score"],
                        }
                    )
            for query in cases["distractors"]:
                response = available.recall(query, top_k=1)
                availability_distractor_passes += int(not response["results"])
            context_response = available.context(
                CONTEXT_TRACE_QUERY,
                max_depth=1,
                max_records=2,
            )
            context_availability_passed = (
                context_response["degraded"] is True
                and context_response["semantic_available"] is False
                and {str(item["vine_id"]) for item in context_response["logic_roots"]}
                == {context_root_id}
                and {str(item["vine_id"]) for item in context_response["evidence"]}
                == {ids["incident"], ids["backup"]}
                and all(
                    item["query_scored"] is False
                    for item in context_response["evidence"]
                )
            )
            competing_response = available.recall(
                COMPETING_MEMORY_QUERY,
                top_k=1,
            )
            competing_availability_passed = (
                {str(item["vine_id"]) for item in competing_response["results"]}
                == competing_ids
                and competing_response["degraded"] is True
                and competing_response["semantic_available"] is False
                and competing_response["competing_pair_auto_expanded"] is True
                and competing_response["competing_memory_detected"] is True
                and len(competing_response["competing_memory_groups"]) == 1
                and competing_response["competing_memory_groups"][0][
                    "resolution_status"
                ]
                == "not_evaluated"
            )
            live_records = {
                str(item["vine_id"]): item for item in available.list_memories()
            }
            live_write_blocked = False
            try:
                available.refresh_live(
                    str(live_changed["vine_id"]),
                    "A degraded reader must not update Live state.",
                )
            except RuntimeError:
                live_write_blocked = True
            live_refresh_availability_passed = (
                live_refresh_ids <= set(live_records)
                and live_records[str(live_original["vine_id"])]["superseded_by"]
                == live_changed["vine_id"]
                and live_records[str(live_changed["vine_id"])]["superseded_by"] is None
                and live_write_blocked
            )

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
    availability_passed = (
        availability_keyword_passes == availability_keyword_total
        and availability_distractor_passes == len(cases["distractors"])
        and context_availability_passed
        and competing_availability_passed
        and live_refresh_availability_passed
    )
    retrieval_index = doctor["retrieval"]
    report = {
        "verdict": (
            "pass"
            if (
                all_queries_passed
                and all_distractors_passed
                and availability_passed
                and context_semantic_passed
                and competing_semantic_passed
                and live_refresh_semantic_passed
            )
            else "fail"
        ),
        "model": embedder.model,
        "dimension": embedder.dimension,
        "memory_count": len(cases["memories"]) + 5,
        "retrieval_memory_count": len(cases["memories"]) + 4,
        "query_count": len(outcomes),
        "categories": categories,
        "distractor_rejection": {
            "passed": distractor_passes,
            "total": len(cases["distractors"]),
        },
        "always_available": {
            "keyword_passed": availability_keyword_passes,
            "keyword_total": availability_keyword_total,
            "distractor_passed": availability_distractor_passes,
            "distractor_total": len(cases["distractors"]),
            "context_trace_passed": context_availability_passed,
            "failures": availability_failures,
            "mode": "encrypted-keyed-predicate-v1",
        },
        "context_trace": {
            "semantic_passed": context_semantic_passed,
            "always_available_passed": context_availability_passed,
            "root_count": 1,
            "evidence_count": 2,
            "max_depth": 1,
            "max_records": 2,
            "semantic_elapsed_ms": round(context_trace_ms, 2),
            "remember_ms": round(context_remember_ms, 2),
            "linked_evidence_query_scored": False,
            "synthesis_performed": False,
        },
        "competing_memory": {
            "semantic_passed": competing_semantic_passed,
            "always_available_passed": competing_availability_passed,
            "requested_top_k": 1,
            "effective_top_k": 2,
            "returned_member_count": 2,
            "protected_topic_basis": True,
            "compatibility_inferred": False,
            "resolution_status": "not_evaluated",
            "semantic_elapsed_ms": round(competing_recall_ms, 2),
        },
        "live_refresh": {
            "semantic_passed": live_refresh_semantic_passed,
            "always_available_persistence_passed": (live_refresh_availability_passed),
            "changed_content_created_version": True,
            "unchanged_content_reused_version": True,
            "history_preserved_with_supersession": True,
            "degraded_write_blocked": True,
            "content_policy": "bounded-seed-crystal-v1",
            "changed_refresh_elapsed_ms": round(live_refresh_ms, 2),
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
