#!/usr/bin/env python3
"""Run bounded local scale, concurrency, and abrupt-recovery qualification."""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import math
import multiprocessing
import os
from pathlib import Path
import statistics
import tempfile
import threading
import time
from typing import Any

import numpy as np

from echo_veil.archive import IndexEntry
from echo_veil.agent_memory import AgentMemory
from echo_veil.persistence import MAX_INDEX_BATCH_SIZE, SQLiteStore
from echo_veil.vectors import cosine_similarity
from echo_veil.vine import Vine, VineState
from echo_veil.workspace import Workspace, WorkspaceConfig

REPORT_SCHEMA = "echo-veil-local-qualification-v1"
DEFAULT_SIZES = (1_000, 10_000, 100_000)
MAX_CORPUS_SIZE = 1_000_000
ABRUPT_BEFORE_COMMIT_EXIT = 86
ABRUPT_AFTER_COMMIT_EXIT = 87
LSH_KEY = b"echo-veil-qualification-key-v1!!"
MIGRATION_LOAD_RECORDS = 48
MIGRATION_LOAD_READERS = 4
MIGRATION_LOAD_READS_PER_READER = 12


class _QualificationEmbedder:
    identity = "qualification:semantic:v1:dimension:32"
    name = "qualification"
    model = "deterministic-semantic-v1"
    dimension = 32
    semantic = True
    default_min_score = 0.44

    @staticmethod
    def _vector() -> np.ndarray:
        value = np.zeros(32, dtype=np.float64)
        value[0] = 1.0
        return value

    def embed_document(self, _text: str) -> np.ndarray:
        return self._vector()

    def embed_documents(self, texts: list[str]) -> list[np.ndarray]:
        return [self._vector() for _ in texts]

    def embed_query(self, _text: str) -> np.ndarray:
        return self._vector()

    def embed_retrieval_queries(self, _text: str) -> tuple[np.ndarray, np.ndarray]:
        value = self._vector()
        return value, value.copy()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--sizes",
        type=int,
        nargs="+",
        default=list(DEFAULT_SIZES),
        help="ordered corpus sizes to qualify",
    )
    parser.add_argument("--dimension", type=int, default=1_024)
    parser.add_argument("--batch-size", type=int, default=MAX_INDEX_BATCH_SIZE)
    parser.add_argument("--queries", type=int, default=12)
    return parser


def _validate_args(args: argparse.Namespace) -> None:
    if (
        not args.sizes
        or any(size <= 0 or size > MAX_CORPUS_SIZE for size in args.sizes)
        or args.sizes != sorted(set(args.sizes))
    ):
        raise ValueError(
            "sizes must be unique increasing integers between 1 and 1000000"
        )
    if not 32 <= args.dimension <= 65_536:
        raise ValueError("dimension must be between 32 and 65536")
    if not 1 <= args.batch_size <= MAX_INDEX_BATCH_SIZE:
        raise ValueError(f"batch size must be between 1 and {MAX_INDEX_BATCH_SIZE}")
    if not 1 <= args.queries <= 32:
        raise ValueError("queries must be between 1 and 32")


def _percentile(values: list[float], percentile: float) -> float:
    ordered = sorted(values)
    return ordered[max(0, math.ceil(percentile * len(ordered)) - 1)]


def _normalized_vector(
    rng: np.random.Generator,
    dimension: int,
) -> np.ndarray:
    vector = rng.standard_normal(dimension, dtype=np.float64)
    vector /= np.linalg.norm(vector)
    return vector


def _target_indices(size: int, query_count: int) -> list[int]:
    count = min(size, query_count)
    return sorted({int(value) for value in np.linspace(0, size - 1, count)})


def _upsert_generated(
    store: SQLiteStore,
    *,
    start: int,
    stop: int,
    dimension: int,
    batch_size: int,
    seed: int,
    targets: set[int] | None = None,
) -> dict[int, np.ndarray]:
    retained: dict[int, np.ndarray] = {}
    rng = np.random.default_rng(seed)
    for batch_start in range(start, stop, batch_size):
        entries: list[IndexEntry] = []
        for index in range(batch_start, min(stop, batch_start + batch_size)):
            vector = _normalized_vector(rng, dimension)
            if targets is not None and index in targets:
                retained[index] = vector.copy()
            entries.append(
                IndexEntry(
                    key=f"record-{index:07d}",
                    anchor=vector,
                    kind="anchor",
                )
            )
        store.index.upsert_many(entries)
    return retained


def _directory_size(path: Path) -> int:
    return sum(item.stat().st_size for item in path.iterdir() if item.is_file())


def _run_scale_tier(
    root: Path,
    *,
    size: int,
    dimension: int,
    batch_size: int,
    query_count: int,
) -> dict[str, Any]:
    tier = root / f"scale-{size}"
    tier.mkdir(mode=0o700)
    database = tier / "index.db"
    targets = set(_target_indices(size, query_count))
    started = time.perf_counter()
    with SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=False) as store:
        queries = _upsert_generated(
            store,
            start=0,
            stop=size,
            dimension=dimension,
            batch_size=batch_size,
            seed=20_260_820 + size,
            targets=targets,
        )
    insert_seconds = time.perf_counter() - started
    storage_bytes = _directory_size(tier)

    opened = time.perf_counter()
    with SQLiteStore(
        database,
        lsh_key=LSH_KEY,
        verify_integrity=True,
    ) as store:
        integrity_open_ms = (time.perf_counter() - opened) * 1_000.0
        search_ms: list[float] = []
        candidate_counts: list[int] = []
        correct = 0
        for index, query in sorted(queries.items()):
            candidates = 0

            def scorer(value: np.ndarray, entry: IndexEntry) -> float:
                nonlocal candidates
                candidates += 1
                return cosine_similarity(value, entry.anchor)

            search_started = time.perf_counter()
            results = store.index.search(query, top_k=5, score_fn=scorer)
            search_ms.append((time.perf_counter() - search_started) * 1_000.0)
            candidate_counts.append(candidates)
            correct += int(bool(results) and results[0][0] == f"record-{index:07d}")
        reopened_count = len(store.index)
        lsh_status = store.lsh_status()
    max_candidate_fraction = max(candidate_counts) / size
    passed = (
        correct == len(queries)
        and reopened_count == size
        and max_candidate_fraction < 0.10
        and lsh_status["schema"] == "echo-veil-lsh-index-v2"
        and lsh_status["bucket_identifiers"] == "hmac-sha256"
    )
    return {
        "passed": passed,
        "records": size,
        "dimension": dimension,
        "queries": len(queries),
        "top_one_correct": correct,
        "insert_seconds": round(insert_seconds, 3),
        "insert_records_per_second": round(size / insert_seconds, 2),
        "integrity_checked_reopen_ms": round(integrity_open_ms, 2),
        "search_mean_ms": round(statistics.fmean(search_ms), 2),
        "search_p95_ms": round(_percentile(search_ms, 0.95), 2),
        "exact_rerank_candidates_mean": round(
            statistics.fmean(candidate_counts),
            2,
        ),
        "exact_rerank_candidates_max": max(candidate_counts),
        "exact_rerank_candidate_fraction_max": round(max_candidate_fraction, 6),
        "storage_bytes": storage_bytes,
        "bytes_per_record": round(storage_bytes / size, 2),
        "reopened_record_count": reopened_count,
        "search_strategy": "keyed-lsh-candidates-plus-exact-rerank",
    }


def _run_concurrent_read_write(
    root: Path,
    *,
    dimension: int,
    batch_size: int,
) -> dict[str, Any]:
    directory = root / "concurrency"
    directory.mkdir(mode=0o700)
    database = directory / "index.db"
    base_records = 1_000
    appended_records = 1_000
    target_index = 0
    with SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=False) as store:
        target = _upsert_generated(
            store,
            start=0,
            stop=base_records,
            dimension=dimension,
            batch_size=batch_size,
            seed=20_260_821,
            targets={target_index},
        )[target_index]

    writer = SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=False)
    readers = [
        SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=False) for _ in range(4)
    ]
    reader_latencies: list[float] = []
    wrong_results = 0
    errors: list[str] = []

    def read_loop(reader: SQLiteStore) -> None:
        nonlocal wrong_results
        try:
            for _ in range(12):
                started = time.perf_counter()
                result = reader.index.search(target, top_k=1)
                reader_latencies.append((time.perf_counter() - started) * 1_000.0)
                wrong_results += int(
                    not result or result[0][0] != f"record-{target_index:07d}"
                )
        except Exception as exc:  # pragma: no cover - reported by the gate
            errors.append(type(exc).__name__)

    def write_loop() -> None:
        try:
            _upsert_generated(
                writer,
                start=base_records,
                stop=base_records + appended_records,
                dimension=dimension,
                batch_size=batch_size,
                seed=20_260_822,
            )
        except Exception as exc:  # pragma: no cover - reported by the gate
            errors.append(type(exc).__name__)

    try:
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = [executor.submit(read_loop, reader) for reader in readers]
            futures.append(executor.submit(write_loop))
            for future in futures:
                future.result()
        final_count = len(writer.index)
    finally:
        writer.close()
        for reader in readers:
            reader.close()

    expected_reads = len(readers) * 12
    passed = (
        not errors
        and wrong_results == 0
        and len(reader_latencies) == expected_reads
        and final_count == base_records + appended_records
    )
    return {
        "passed": passed,
        "reader_connections": len(readers),
        "reader_operations": len(reader_latencies),
        "wrong_results": wrong_results,
        "writer_records_committed": final_count - base_records,
        "reader_p95_ms": (
            None
            if not reader_latencies
            else round(_percentile(reader_latencies, 0.95), 2)
        ),
        "error_count": len(errors),
    }


def _abrupt_worker(database_value: str, mode: str, dimension: int) -> None:
    database = Path(database_value)
    vector = np.zeros(dimension, dtype=np.float64)
    vector[0] = 1.0
    store = SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=False)
    if mode == "before-commit":
        prepared = store._prepare_index_upsert(
            IndexEntry(key="abrupt-before", anchor=vector, kind="anchor")
        )
        with store._lock:
            store._begin_locked()
            key, kind, payload, entry_dimension, signatures = prepared
            store._upsert_metadata_locked(key, kind, payload, entry_dimension)
            store._replace_ann_buckets_locked(key, signatures)
            os._exit(ABRUPT_BEFORE_COMMIT_EXIT)
    if mode == "after-commit":
        store.index.upsert("abrupt-after", vector)
        os._exit(ABRUPT_AFTER_COMMIT_EXIT)
    os._exit(85)


def _run_abrupt_recovery(root: Path, *, dimension: int) -> dict[str, Any]:
    directory = root / "abrupt-recovery"
    directory.mkdir(mode=0o700)
    database = directory / "index.db"
    with SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=False):
        pass

    context = multiprocessing.get_context("spawn")
    before = context.Process(
        target=_abrupt_worker,
        args=(str(database), "before-commit", dimension),
    )
    before.start()
    before.join(15.0)
    if before.is_alive():
        before.kill()
        before.join(5.0)

    with SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=True) as store:
        rolled_back = len(store.index) == 0

    after = context.Process(
        target=_abrupt_worker,
        args=(str(database), "after-commit", dimension),
    )
    after.start()
    after.join(15.0)
    if after.is_alive():
        after.kill()
        after.join(5.0)

    query = np.zeros(dimension, dtype=np.float64)
    query[0] = 1.0
    with SQLiteStore(database, lsh_key=LSH_KEY, verify_integrity=True) as store:
        result = store.index.search(query, top_k=1)
        committed_survived = result == [("abrupt-after", 1.0)]

    passed = (
        before.exitcode == ABRUPT_BEFORE_COMMIT_EXIT
        and after.exitcode == ABRUPT_AFTER_COMMIT_EXIT
        and rolled_back
        and committed_survived
    )
    return {
        "passed": passed,
        "uncommitted_transaction_rolled_back": rolled_back,
        "committed_transaction_survived": committed_survived,
        "before_commit_exit_observed": (before.exitcode == ABRUPT_BEFORE_COMMIT_EXIT),
        "after_commit_exit_observed": after.exitcode == ABRUPT_AFTER_COMMIT_EXIT,
        "simulation": "abrupt-process-exit-with-sqlite-wal-full-sync",
        "physical_power_loss_claimed": False,
    }


def _run_long_duration_lifecycle() -> dict[str, Any]:
    start = 1_700_000_000.0
    anchor = np.array([1.0, 0.0], dtype=np.float64)
    unrelated = np.array([0.0, 1.0], dtype=np.float64)
    workspace = Workspace(WorkspaceConfig(capacity=8))
    stale = workspace.add(
        Vine(
            "long-duration stale record",
            anchor,
            created_at=start,
            last_touched=start,
        )
    )
    locked = workspace.add(
        Vine(
            "long-duration locked record",
            anchor,
            created_at=start,
            last_touched=start,
        )
    )
    workspace.lock(locked.vine_id)
    checkpoints_days = (0, 1, 30, 180, 364, 365)
    stale_scores: list[float] = []
    demoted = False
    evicted = False
    for days in checkpoints_days:
        report = workspace.run_decay_cycle(
            unrelated,
            now=start + days * 24 * 60 * 60,
        )
        demoted = demoted or stale.vine_id in report["demoted"]
        evicted = evicted or stale.vine_id in report["evicted"]
        stale_scores.append(stale.score)
    monotonic = all(
        left >= right for left, right in zip(stale_scores, stale_scores[1:])
    )
    passed = (
        demoted
        and evicted
        and stale.state == VineState.EVICTED
        and locked.state == VineState.ACTIVE
        and locked.locked
        and monotonic
    )
    return {
        "passed": passed,
        "simulated_days": checkpoints_days[-1],
        "checkpoints": len(checkpoints_days),
        "stale_demoted": demoted,
        "stale_evicted": evicted,
        "locked_record_survived": (locked.state == VineState.ACTIVE and locked.locked),
        "stale_scores_monotonic": monotonic,
        "wall_clock_wait_claimed": False,
    }


def _run_migration_under_load(root: Path) -> dict[str, Any]:
    state_dir = root / "migration-under-load"
    state_dir.mkdir(mode=0o700)
    profile = "qualification"
    embedder = _QualificationEmbedder()
    reader_barrier = threading.Barrier(MIGRATION_LOAD_READERS + 1)
    with AgentMemory(
        state_dir,
        profile=profile,
        capacity=MIGRATION_LOAD_RECORDS + 8,
        embed=embedder,
    ) as memory:
        for index in range(MIGRATION_LOAD_RECORDS):
            memory.remember(
                f"migration record {index:03d}",
                f"Protected migration record {index:03d} remains readable.",
                provenance=["qualification:migration-under-load"],
            )
        backup = memory.backup_create(root / "migration-under-load-backup")
        first = memory.migrate_record_envelope_v3(
            confirm=True,
            batch_size=1,
            verified_backup=backup,
        )
        if first["state"] != "migrating":
            raise RuntimeError("migration-under-load fixture completed unexpectedly")

        def migrate() -> dict[str, Any]:
            reader_barrier.wait(timeout=10.0)
            result = first
            calls = 1
            while result["state"] != "verified" and calls <= 1_000:
                result = memory.migrate_record_envelope_v3(
                    confirm=True,
                    batch_size=2,
                )
                calls += 1
            return {
                "calls": calls,
                "verified": result["state"] == "verified",
                "remaining_v2_records": int(result["remaining_v2_records"]),
                "remaining_v2_lifecycle_records": int(
                    result["remaining_v2_lifecycle_records"]
                ),
            }

        def read() -> dict[str, int]:
            reader_barrier.wait(timeout=10.0)
            operations = 0
            incomplete = 0
            empty_recall = 0
            for _index in range(MIGRATION_LOAD_READS_PER_READER):
                listed = memory.list_memories(limit=MIGRATION_LOAD_RECORDS + 1)
                incomplete += int(len(listed) != MIGRATION_LOAD_RECORDS)
                recalled = memory.recall("Which migration records remain readable?")
                empty_recall += int(not recalled["results"])
                operations += 2
            return {
                "operations": operations,
                "incomplete": incomplete,
                "empty_recall": empty_recall,
            }

        with ThreadPoolExecutor(max_workers=MIGRATION_LOAD_READERS + 1) as executor:
            migration_future = executor.submit(migrate)
            reader_futures = [
                executor.submit(read) for _index in range(MIGRATION_LOAD_READERS)
            ]
            migration = migration_future.result()
            reader_reports = [future.result() for future in reader_futures]

        final = memory.doctor()["record_envelope"]
        final_count = len(memory.list_memories(limit=MIGRATION_LOAD_RECORDS + 1))

    with AgentMemory(
        state_dir,
        profile=profile,
        capacity=MIGRATION_LOAD_RECORDS + 8,
        embed=embedder,
    ) as reopened:
        restart_count = len(reopened.list_memories(limit=MIGRATION_LOAD_RECORDS + 1))
        restart_state = reopened.doctor()["record_envelope"]["migration_state"]

    read_operations = sum(item["operations"] for item in reader_reports)
    incomplete_reads = sum(item["incomplete"] for item in reader_reports)
    empty_recalls = sum(item["empty_recall"] for item in reader_reports)
    passed = (
        migration["verified"] is True
        and migration["remaining_v2_records"] == 0
        and migration["remaining_v2_lifecycle_records"] == 0
        and final["migration_state"] == "verified"
        and final_count == MIGRATION_LOAD_RECORDS
        and restart_count == MIGRATION_LOAD_RECORDS
        and restart_state == "verified"
        and read_operations
        == MIGRATION_LOAD_READERS * MIGRATION_LOAD_READS_PER_READER * 2
        and incomplete_reads == 0
        and empty_recalls == 0
    )
    return {
        "passed": passed,
        "records": MIGRATION_LOAD_RECORDS,
        "reader_workers": MIGRATION_LOAD_READERS,
        "reader_operations": read_operations,
        "incomplete_reads": incomplete_reads,
        "empty_recalls": empty_recalls,
        "migration_calls": migration["calls"],
        "migration_verified": migration["verified"],
        "restart_verified": restart_state == "verified",
        "preflight_protocol": "preflight_v2",
    }


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _validate_args(args)
    with tempfile.TemporaryDirectory(prefix="echo-veil-qualification-") as temporary:
        root = Path(temporary).resolve(strict=True)
        scale = [
            _run_scale_tier(
                root,
                size=size,
                dimension=args.dimension,
                batch_size=args.batch_size,
                query_count=args.queries,
            )
            for size in args.sizes
        ]
        concurrency = _run_concurrent_read_write(
            root,
            dimension=args.dimension,
            batch_size=args.batch_size,
        )
        abrupt_recovery = _run_abrupt_recovery(root, dimension=args.dimension)
        lifecycle = _run_long_duration_lifecycle()
        migration_under_load = _run_migration_under_load(root)

    passed = (
        all(item["passed"] is True for item in scale)
        and concurrency["passed"] is True
        and abrupt_recovery["passed"] is True
        and lifecycle["passed"] is True
        and migration_under_load["passed"] is True
    )
    report = {
        "schema": REPORT_SCHEMA,
        "verdict": "pass" if passed else "fail",
        "scale": scale,
        "concurrent_read_write": concurrency,
        "abrupt_recovery": abrupt_recovery,
        "long_duration_lifecycle": lifecycle,
        "migration_under_load": migration_under_load,
        "scope": {
            "measured": [
                "durable keyed-LSH candidate lookup",
                "exact rerank recall for deterministic synthetic vectors",
                "SQLite storage growth and integrity-checked reopen",
                "concurrent WAL readers with one bounded writer",
                "abrupt process exit before and after commit",
                "365-day simulated lifecycle decay and locked-record survival",
                "bounded record-envelope v3 migration under concurrent read load",
            ],
            "not_measured": [
                "semantic embedding quality",
                "host capture or answer generation",
                "distributed or exabyte-scale storage",
                "physical device power removal or controller-cache loss",
            ],
        },
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
