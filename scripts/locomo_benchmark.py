#!/usr/bin/env python3
"""Evaluate Echo Veil retrieval on LoCoMo's generated observation database."""

from __future__ import annotations

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import json
import math
from pathlib import Path
import re
import statistics
import tempfile
import time
from typing import Any

from echo_veil.agent_memory import (
    AgentMemory,
    DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    DEFAULT_OLLAMA_MODEL,
    DEFAULT_OLLAMA_URL,
    OllamaTextEmbedder,
)

REPORT_SCHEMA = "echo-veil-locomo-retrieval-v1"
PINNED_DATASET_SHA256 = (
    "79fa87e90f04081343b8c8debecb80a9a6842b76a7aa537dc9fdf651ea698ff4"
)
MAX_DATASET_BYTES = 8 * 1024 * 1024
MAX_SAMPLES = 10
MAX_QUESTIONS_PER_SAMPLE = 500
MAX_SESSIONS_PER_SAMPLE = 64
MAX_OBSERVATION_RECORDS_PER_SAMPLE = 512
MAX_OBSERVATION_CHARS = 4_096
SESSION_KEY = re.compile(r"^session_([1-9][0-9]*)_observation$")
EVIDENCE_TOKEN = re.compile(r"D([1-9][0-9]*):0*([1-9][0-9]*)")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--expected-sha256", default=PINNED_DATASET_SHA256)
    parser.add_argument("--model", default=DEFAULT_OLLAMA_MODEL)
    parser.add_argument(
        "--dimension",
        type=int,
        default=DEFAULT_OLLAMA_EMBEDDING_DIMENSION,
    )
    parser.add_argument("--ollama-url", default=DEFAULT_OLLAMA_URL)
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--limit-samples", type=int, default=MAX_SAMPLES)
    parser.add_argument("--questions-per-sample", type=int, default=0)
    return parser


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _validate_digest(value: str) -> str:
    clean = value.strip().lower()
    if len(clean) != 64 or any(
        character not in "0123456789abcdef" for character in clean
    ):
        raise ValueError("expected dataset SHA-256 must be 64 lowercase hex characters")
    return clean


def _load_dataset(path: Path, expected_sha256: str) -> tuple[list[dict[str, Any]], str]:
    source = path.expanduser().absolute()
    if source.is_symlink() or not source.is_file():
        raise ValueError("LoCoMo dataset must be a regular non-symlink file")
    size = source.stat().st_size
    if not 0 < size <= MAX_DATASET_BYTES:
        raise ValueError("LoCoMo dataset has an invalid size")
    encoded = source.read_bytes()
    digest = hashlib.sha256(encoded).hexdigest()
    if digest != _validate_digest(expected_sha256):
        raise ValueError("LoCoMo dataset SHA-256 does not match the reviewed input")
    try:
        decoded = json.loads(encoded)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("LoCoMo dataset is not valid UTF-8 JSON") from exc
    if not isinstance(decoded, list) or not 1 <= len(decoded) <= MAX_SAMPLES:
        raise ValueError("LoCoMo dataset must contain between 1 and 10 samples")
    samples: list[dict[str, Any]] = []
    sample_ids: set[str] = set()
    for raw in decoded:
        if not isinstance(raw, dict) or not {
            "conversation",
            "observation",
            "qa",
            "sample_id",
        } <= set(raw):
            raise ValueError("LoCoMo sample fields are invalid")
        sample_id = raw["sample_id"]
        if (
            not isinstance(sample_id, str)
            or not re.fullmatch(r"[a-z0-9-]{1,40}", sample_id)
            or sample_id in sample_ids
        ):
            raise ValueError("LoCoMo sample ID is invalid or duplicated")
        sample_ids.add(sample_id)
        if not isinstance(raw["conversation"], dict):
            raise ValueError("LoCoMo conversation must be an object")
        if (
            not isinstance(raw["observation"], dict)
            or not 1 <= len(raw["observation"]) <= MAX_SESSIONS_PER_SAMPLE
        ):
            raise ValueError("LoCoMo observations have an invalid shape")
        if not isinstance(raw["qa"], list) or not 1 <= len(raw["qa"]) <= (
            MAX_QUESTIONS_PER_SAMPLE
        ):
            raise ValueError("LoCoMo QA set has an invalid shape")
        samples.append(raw)
    return samples, digest


def _normalize_evidence_id(value: str) -> str:
    match = EVIDENCE_TOKEN.fullmatch(value)
    if match is None:
        raise ValueError("LoCoMo observation evidence ID is invalid")
    return f"D{int(match.group(1))}:{int(match.group(2))}"


def _session_records(raw: object) -> list[tuple[str, str, set[str]]]:
    if not isinstance(raw, dict) or not raw:
        raise ValueError("LoCoMo session observation must be a non-empty object")
    records: list[tuple[str, str, set[str]]] = []
    for speaker, observations in raw.items():
        if not isinstance(speaker, str) or not speaker.strip():
            raise ValueError("LoCoMo observation speaker is invalid")
        if not isinstance(observations, list) or not observations:
            raise ValueError("LoCoMo speaker observations must be non-empty")
        for observation in observations:
            if (
                not isinstance(observation, list)
                or len(observation) != 2
                or not isinstance(observation[0], str)
                or not observation[0].strip()
            ):
                raise ValueError("LoCoMo observation row is invalid")
            statement, evidence_raw = observation
            if isinstance(evidence_raw, str):
                evidence_values = [evidence_raw]
            elif (
                isinstance(evidence_raw, list)
                and evidence_raw
                and all(isinstance(item, str) for item in evidence_raw)
            ):
                evidence_values = evidence_raw
            else:
                raise ValueError("LoCoMo observation evidence ID is invalid")
            evidence_ids = {
                _normalize_evidence_id(evidence_id) for evidence_id in evidence_values
            }
            clean_statement = statement.strip()
            if len(clean_statement) > MAX_OBSERVATION_CHARS:
                raise ValueError(
                    "LoCoMo session observation exceeds the bounded record size"
                )
            records.append((speaker.strip(), clean_statement, evidence_ids))
    return records


def _session_timestamp(conversation: dict[str, Any], session_number: int) -> float:
    value = conversation.get(f"session_{session_number}_date_time")
    if not isinstance(value, str):
        raise ValueError("LoCoMo session timestamp is missing")
    try:
        parsed = datetime.strptime(value, "%I:%M %p on %d %B, %Y")
    except ValueError as exc:
        raise ValueError("LoCoMo session timestamp is invalid") from exc
    return parsed.replace(tzinfo=timezone.utc).timestamp()


def _question_evidence(evidence: object) -> tuple[set[int] | None, set[str] | None]:
    if not isinstance(evidence, list) or not all(
        isinstance(item, str) for item in evidence
    ):
        raise ValueError("LoCoMo question evidence must be a string list")
    sessions: set[int] = set()
    evidence_ids: set[str] = set()
    for item in evidence:
        matches = list(EVIDENCE_TOKEN.finditer(item))
        residual = EVIDENCE_TOKEN.sub("", item)
        if not matches or residual.strip(" ;,"):
            return None, None
        sessions.update(int(match.group(1)) for match in matches)
        evidence_ids.update(
            f"D{int(match.group(1))}:{int(match.group(2))}" for match in matches
        )
    return sessions, evidence_ids


def _question_rows(sample: dict[str, Any], limit: int) -> list[dict[str, Any]]:
    rows = sample["qa"] if limit == 0 else sample["qa"][:limit]
    for row in rows:
        if (
            not isinstance(row, dict)
            or not isinstance(row.get("question"), str)
            or not row["question"].strip()
            or isinstance(row.get("category"), bool)
            or not isinstance(row.get("category"), int)
        ):
            raise ValueError("LoCoMo question row is invalid")
        _question_evidence(row.get("evidence"))
    return rows


def _run_sample(
    state_dir: Path,
    sample: dict[str, Any],
    *,
    embedder: OllamaTextEmbedder,
    top_k: int,
    question_limit: int,
    dataset_digest: str,
) -> dict[str, Any]:
    sample_id = str(sample["sample_id"])
    profile = f"locomo-{sample_id}"
    session_by_vine: dict[str, int] = {}
    session_numbers: set[int] = set()
    observation_evidence: set[str] = set()
    ingest_started = time.perf_counter()
    observations: list[tuple[int, object]] = []
    for key, raw_observation in sample["observation"].items():
        if not isinstance(key, str):
            raise ValueError("LoCoMo observation session key is invalid")
        match = SESSION_KEY.fullmatch(key)
        if match is None:
            raise ValueError("LoCoMo observation session key is invalid")
        observations.append((int(match.group(1)), raw_observation))
    with AgentMemory(
        state_dir,
        profile=profile,
        capacity=MAX_OBSERVATION_RECORDS_PER_SAMPLE,
        embed=embedder,
    ) as memory:
        for session_number, raw_observation in sorted(observations):
            session_numbers.add(session_number)
            timestamp = _session_timestamp(sample["conversation"], session_number)
            date_text = sample["conversation"][f"session_{session_number}_date_time"]
            for speaker, statement, evidence_ids in _session_records(raw_observation):
                observation_evidence.update(evidence_ids)
                primary_evidence = sorted(evidence_ids)[0]
                record = memory.remember(
                    f"{speaker} {primary_evidence}: {statement}",
                    f"Session date: {date_text}. {statement}",
                    provenance=[
                        "benchmark:locomo-observations",
                        f"dataset-sha256:{dataset_digest}",
                        f"sample:{sample_id}",
                    ],
                    effective_at=timestamp,
                )
                session_by_vine[str(record["vine_id"])] = session_number
    ingest_seconds = time.perf_counter() - ingest_started

    question_metrics: list[dict[str, Any]] = []
    latency_ms: list[float] = []
    hard_negative_passes = 0
    conversation = sample["conversation"]
    speakers = [
        value
        for key, value in conversation.items()
        if key in {"speaker_a", "speaker_b"} and isinstance(value, str)
    ]
    with AgentMemory(
        state_dir,
        profile=profile,
        capacity=MAX_OBSERVATION_RECORDS_PER_SAMPLE,
        embed=embedder,
    ) as memory:
        if len(memory.list_memories(limit=MAX_OBSERVATION_RECORDS_PER_SAMPLE)) != len(
            session_by_vine
        ):
            raise RuntimeError("LoCoMo profile did not persist every observation")
        for row in _question_rows(sample, question_limit):
            expected, query_evidence_ids = _question_evidence(row["evidence"])
            capture_complete = (
                query_evidence_ids is not None
                and bool(query_evidence_ids)
                and query_evidence_ids <= observation_evidence
            )
            started = time.perf_counter()
            response = memory.recall(
                row["question"],
                top_k=min(20, top_k * 4),
                retrieval_mode="supporting",
            )
            latency_ms.append((time.perf_counter() - started) * 1_000.0)
            returned: list[int] = []
            for item in response["results"]:
                session_number = session_by_vine[str(item["vine_id"])]
                if session_number not in returned:
                    returned.append(session_number)
                if len(returned) == top_k:
                    break
            relevant = 0 if expected is None else len(expected.intersection(returned))
            question_metrics.append(
                {
                    "category": int(row["category"]),
                    "scored": expected is not None and bool(expected),
                    "capture_complete": capture_complete,
                    "invalid_evidence": expected is None,
                    "top_one": bool(
                        expected is not None and returned and returned[0] in expected
                    ),
                    "all_evidence": (
                        expected is not None
                        and bool(expected)
                        and expected <= set(returned)
                    ),
                    "recall": (
                        0.0
                        if expected is None or not expected
                        else relevant / len(expected)
                    ),
                    "precision": 0.0 if not returned else relevant / len(returned),
                }
            )

        hard_negatives = ["purple llama tungsten"]
        hard_negatives.extend(
            f"What is {speaker}'s passport number?" for speaker in speakers[:1]
        )
        for query in hard_negatives:
            response = memory.recall(query, top_k=top_k)
            hard_negative_passes += int(not response["results"])

    scored = [item for item in question_metrics if item["scored"]]
    captured = [item for item in scored if item["capture_complete"]]
    categories: dict[str, dict[str, Any]] = {}
    by_category: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for item in captured:
        by_category[int(item["category"])].append(item)
    for category, rows in sorted(by_category.items()):
        categories[str(category)] = _aggregate_questions(rows)
    return {
        "sample_id": sample_id,
        "sessions": len(session_numbers),
        "observation_records": len(session_by_vine),
        "observation_evidence_ids": len(observation_evidence),
        "questions": len(question_metrics),
        "scored_questions": len(scored),
        "capture_complete_questions": len(captured),
        "unscored_missing_evidence": sum(
            not item["scored"] and not item["invalid_evidence"]
            for item in question_metrics
        ),
        "unscored_invalid_evidence": sum(
            bool(item["invalid_evidence"]) for item in question_metrics
        ),
        "retrieval": _aggregate_questions(captured),
        "capture_plus_retrieval": _aggregate_questions(scored),
        "categories": categories,
        "hard_negative_passed": hard_negative_passes,
        "hard_negative_total": 1 + min(1, len(speakers)),
        "ingest_seconds": round(ingest_seconds, 2),
        "recall_mean_ms": round(statistics.fmean(latency_ms), 2),
        "recall_p95_ms": round(_percentile(latency_ms, 0.95), 2),
        "restart_persistence": True,
    }


def _aggregate_questions(rows: list[dict[str, Any]]) -> dict[str, Any]:
    if not rows:
        return {
            "count": 0,
            "top_one_rate": None,
            "all_evidence_rate": None,
            "mean_recall_at_k": None,
            "mean_precision_at_k": None,
        }
    return {
        "count": len(rows),
        "top_one_rate": round(
            sum(bool(item["top_one"]) for item in rows) / len(rows),
            4,
        ),
        "all_evidence_rate": round(
            sum(bool(item["all_evidence"]) for item in rows) / len(rows),
            4,
        ),
        "mean_recall_at_k": round(
            statistics.fmean(float(item["recall"]) for item in rows),
            4,
        ),
        "mean_precision_at_k": round(
            statistics.fmean(float(item["precision"]) for item in rows),
            4,
        ),
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if not 1 <= args.top_k <= 20:
        raise ValueError("top-k must be between 1 and 20")
    if not 1 <= args.limit_samples <= MAX_SAMPLES:
        raise ValueError("sample limit must be between 1 and 10")
    if not 0 <= args.questions_per_sample <= MAX_QUESTIONS_PER_SAMPLE:
        raise ValueError("questions-per-sample must be between 0 and 500")
    samples, dataset_digest = _load_dataset(args.dataset, args.expected_sha256)
    embedder = OllamaTextEmbedder(
        model=args.model,
        dimension=args.dimension,
        base_url=args.ollama_url,
    )
    try:
        with tempfile.TemporaryDirectory(prefix="echo-veil-locomo-") as temporary:
            state_dir = Path(temporary).resolve(strict=True)
            sample_reports = [
                _run_sample(
                    state_dir,
                    sample,
                    embedder=embedder,
                    top_k=args.top_k,
                    question_limit=args.questions_per_sample,
                    dataset_digest=dataset_digest,
                )
                for sample in samples[: args.limit_samples]
            ]
    finally:
        embedder.close()

    total_scored = sum(item["scored_questions"] for item in sample_reports)
    total_captured = sum(item["capture_complete_questions"] for item in sample_reports)

    def aggregate_reports(field: str) -> dict[str, Any]:
        total = sum(int(item[field]["count"]) for item in sample_reports)
        if not total:
            return _aggregate_questions([])
        return {
            "count": total,
            **{
                metric: round(
                    sum(
                        int(item[field]["count"]) * float(item[field][metric])
                        for item in sample_reports
                        if int(item[field]["count"])
                    )
                    / total,
                    4,
                )
                for metric in (
                    "top_one_rate",
                    "all_evidence_rate",
                    "mean_recall_at_k",
                    "mean_precision_at_k",
                )
            },
        }

    retrieval_aggregate = aggregate_reports("retrieval")
    capture_plus_retrieval = aggregate_reports("capture_plus_retrieval")

    hard_negative_passed = sum(item["hard_negative_passed"] for item in sample_reports)
    hard_negative_total = sum(item["hard_negative_total"] for item in sample_reports)
    report = {
        "schema": REPORT_SCHEMA,
        "dataset": {
            "name": "LoCoMo",
            "sha256": dataset_digest,
            "capture_source": "upstream-generated-session-observations",
            "raw_transcripts_ingested": False,
        },
        "model": embedder.model,
        "dimension": embedder.dimension,
        "top_k": args.top_k,
        "retrieval_mode": "supporting",
        "supporting_evidence_only": True,
        "samples": sample_reports,
        "aggregate": {
            "samples": len(sample_reports),
            "sessions": sum(item["sessions"] for item in sample_reports),
            "observation_records": sum(
                item["observation_records"] for item in sample_reports
            ),
            "questions": sum(item["questions"] for item in sample_reports),
            "scored_questions": total_scored,
            "capture_complete_questions": total_captured,
            "unscored_missing_evidence": sum(
                item["unscored_missing_evidence"] for item in sample_reports
            ),
            "unscored_invalid_evidence": sum(
                item["unscored_invalid_evidence"] for item in sample_reports
            ),
            "top_one_rate": retrieval_aggregate["top_one_rate"],
            "all_evidence_rate": retrieval_aggregate["all_evidence_rate"],
            "mean_recall_at_k": retrieval_aggregate["mean_recall_at_k"],
            "mean_precision_at_k": retrieval_aggregate["mean_precision_at_k"],
            "retrieval_on_captured_evidence": retrieval_aggregate,
            "capture_plus_retrieval": capture_plus_retrieval,
            "hard_negative_passed": hard_negative_passed,
            "hard_negative_total": hard_negative_total,
        },
        "end_to_end_answer_quality": {
            "status": "not_run",
            "reason": "retrieval-only run has no pinned reader and official judge",
        },
        "limitations": [
            "LoCoMo generated observations measure retrieval after host-side capture, not capture quality.",
            "Questions without annotated evidence are reported but excluded from retrieval rates.",
            "No universal product comparison follows from one dataset or retrieval-only metrics.",
        ],
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
