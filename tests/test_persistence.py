from __future__ import annotations

import os
import sqlite3
import stat
import time
from pathlib import Path

import numpy as np
import pytest

from echo_veil import (
    AesGcmCryptoShield,
    Oracle,
    SQLiteStore,
    VineState,
    WorkspaceConfig,
)
from echo_veil.archive import EvictionRecord
from echo_veil.capability import CapabilityStatus
from echo_veil.vectors import cosine_similarity


class _FailingMetadataStore(SQLiteStore):
    fail_metadata_write = True

    def _upsert_metadata_locked(
        self,
        key: str,
        kind: str,
        payload: bytes,
        dimension: int,
    ) -> None:
        if self.fail_metadata_write:
            raise OSError("simulated metadata failure")
        super()._upsert_metadata_locked(key, kind, payload, dimension)


def test_sqlite_store_persists_plain_index_and_archive_across_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "echo-veil.db"
    with SQLiteStore(path) as store:
        store.index.upsert("memory", np.array([1.0, 0.0]))
        store.archive.put("memory", b"cold payload")
        assert store.index.search(np.array([1.0, 0.0]), top_k=1) == [("memory", 1.0)]
        assert store.archive.get("memory") == b"cold payload"

    with SQLiteStore(path) as restored:
        assert restored.index.search(np.array([1.0, 0.0]), top_k=1) == [("memory", 1.0)]
        assert restored.archive.get("memory") == b"cold payload"
        assert restored.index.dimension == 2
        restored.verify_integrity()


def test_commits_are_visible_to_another_open_store(tmp_path: Path) -> None:
    path = tmp_path / "shared.db"
    first = SQLiteStore(path)
    second = SQLiteStore(path)
    try:
        first.index.upsert("shared", np.array([1.0, 0.0]))
        first.archive.put("shared", b"shared payload")

        assert second.index.search(np.array([1.0, 0.0]), top_k=1) == [("shared", 1.0)]
        assert second.archive.get("shared") == b"shared payload"
    finally:
        second.close()
        first.close()


def test_sqlite_eviction_transaction_rolls_back_both_tiers_on_failure(
    tmp_path: Path,
) -> None:
    store = _FailingMetadataStore(tmp_path / "rollback.db")
    record = EvictionRecord(
        key="rollback",
        anchor=np.array([1.0, 0.0]),
        kind="anchor",
        archive_payload=b"compressed payload",
        dimension=2,
    )

    with pytest.raises(OSError, match="metadata failure"):
        store.commit_evictions([record])

    assert len(store.index) == 0
    assert len(store.archive) == 0

    store.fail_metadata_write = False
    store.commit_evictions([record])
    assert len(store.index) == 1
    assert len(store.archive) == 1
    store.close()


def test_oracle_retries_failed_transaction_without_pruning(
    tmp_path: Path,
) -> None:
    store = _FailingMetadataStore(tmp_path / "oracle-retry.db")
    oracle = Oracle(
        WorkspaceConfig(capacity=2, pressure_evict_at=0.0),
        storage=store,
    )
    vine = oracle.sprout("retry", np.array([0.0, 1.0]))
    now = time.time()
    oracle.observe(np.array([1.0, 0.0]), now=now)

    with pytest.raises(OSError, match="metadata failure"):
        oracle.observe(
            np.array([1.0, 0.0]),
            now=now + 31 * 60,
            cycles_since_twilight={vine.vine_id: 5},
        )

    assert vine.state == VineState.EVICTED
    assert oracle.workspace.get(vine.vine_id) is vine
    assert len(store.index) == 0
    assert len(store.archive) == 0

    store.fail_metadata_write = False
    oracle.observe(np.array([1.0, 0.0]), now=now + 31 * 60 + 1)
    assert oracle.workspace.get(vine.vine_id) is None
    assert len(store.index) == 1
    assert len(store.archive) == 1
    store.close()


def test_aes_protected_eviction_is_searchable_after_restart(
    tmp_path: Path,
) -> None:
    path = tmp_path / "protected.db"
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    store = SQLiteStore(path)
    oracle = Oracle(
        WorkspaceConfig(capacity=2, pressure_evict_at=0.0),
        shield=shield,
        environment="staging",
        storage=store,
    )
    vine = oracle.sprout("protected", np.array([0.0, 1.0]))
    now = time.time()
    oracle.observe(np.array([1.0, 0.0]), now=now)
    oracle.observe(
        np.array([1.0, 0.0]),
        now=now + 31 * 60,
        cycles_since_twilight={vine.vine_id: 5},
    )
    archived = store.archive.get(vine.vine_id)
    assert archived is not None
    store.close()

    restored = SQLiteStore(path)
    restored_oracle = Oracle(
        shield=shield,
        environment="staging",
        storage=restored,
    )
    assert restored_oracle.search_index(np.array([0.0, 1.0]), top_k=1)[0] == (
        vine.vine_id,
        pytest.approx(1.0),
    )
    assert restored.archive.get(vine.vine_id) == archived
    assert restored_oracle.archived_metadata(vine.vine_id) == {
        "topic": "protected",
        "created_at": vine.created_at,
        "last_touched": vine.last_touched,
        "score": vine.score,
        "state": "evicted",
    }
    restored.close()


def test_durable_staging_configuration_reports_only_crypto_blocker(
    tmp_path: Path,
) -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    with SQLiteStore(tmp_path / "ready.db") as store:
        oracle = Oracle(
            shield=shield,
            environment="staging",
            storage=store,
        )
        report = oracle.capability_report()

        assert report.production_blockers == (
            "AES-GCM does not satisfy the production enclave profile.",
        )
        assert report.storage_backend.status == CapabilityStatus.READY
        assert report.persistence.status == CapabilityStatus.READY
        assert report.vector_index_backend.status == CapabilityStatus.READY
        assert report.overall_status == CapabilityStatus.BLOCKED
        assert not any("linear" in warning.lower() for warning in report.warnings)


def test_in_memory_sqlite_is_not_reported_as_durable() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    with SQLiteStore(":memory:") as store:
        oracle = Oracle(
            shield=shield,
            environment="staging",
            storage=store,
        )
        report = oracle.capability_report()

        assert report.persistence.status == CapabilityStatus.BLOCKED
        assert report.production_blockers


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_database_file_permissions_are_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "private.db"
    with SQLiteStore(path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600


def test_unknown_schema_version_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "future.db"
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()

    with pytest.raises(RuntimeError, match="unsupported.*schema version"):
        SQLiteStore(path)


def test_malformed_existing_schema_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "malformed.db"
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE metadata_index (wrong_column TEXT)")
    connection.close()

    with pytest.raises(RuntimeError, match="schema mismatch"):
        SQLiteStore(path)


def test_closed_store_rejects_access(tmp_path: Path) -> None:
    store = SQLiteStore(tmp_path / "closed.db")
    store.close()
    store.close()

    with pytest.raises(RuntimeError, match="closed"):
        len(store.index)


def test_oracle_rejects_incomplete_storage_backend() -> None:
    with pytest.raises(TypeError, match="commit_evictions"):
        Oracle(storage=object())  # type: ignore[arg-type]


def test_active_workspace_is_checkpointed_and_restored(tmp_path: Path) -> None:
    path = tmp_path / "active.db"
    key = AesGcmCryptoShield.generate_key()
    shield = AesGcmCryptoShield(key)
    with SQLiteStore(path) as store:
        oracle = Oracle(shield=shield, environment="staging", storage=store)
        primary = oracle.sprout("primary", np.array([1.0, 0.0]))
        secondary = oracle.sprout("secondary", np.array([0.0, 1.0]))
        oracle.lock(primary.vine_id)
        oracle.set_crests([primary.vine_id, secondary.vine_id])
        now = time.time()
        oracle.observe(np.array([1.0, 0.0]), now=now)
        current_secondary = oracle.workspace.get(secondary.vine_id)
        assert current_secondary is not None
        assert current_secondary.state == VineState.TWILIGHT

    with SQLiteStore(path) as restored_store:
        restored = Oracle(
            shield=AesGcmCryptoShield(key),
            environment="staging",
            storage=restored_store,
        )
        restored_primary = restored.workspace.get(primary.vine_id)
        restored_secondary = restored.workspace.get(secondary.vine_id)
        assert restored_primary is not None and restored_primary.locked
        assert restored_secondary is not None
        assert restored_secondary.state == VineState.TWILIGHT
        assert restored.workspace.tidal_split() == {"primary": 0.7, "secondary": 0.18}
        restored.reinforce(secondary.vine_id, now=now + 1)
        reinforced = restored.workspace.get(secondary.vine_id)
        assert reinforced is not None and reinforced.state == VineState.ACTIVE


def test_sqlite_lsh_restricts_exact_reranking_to_candidates(tmp_path: Path) -> None:
    rng = np.random.default_rng(20260715)
    vectors = [rng.normal(size=32) for _ in range(256)]
    with SQLiteStore(tmp_path / "ann.db") as store:
        for index, vector in enumerate(vectors):
            store.index.upsert(str(index), vector)
        scored = 0

        def counting_scorer(query, entry):
            nonlocal scored
            scored += 1
            return cosine_similarity(query, entry.anchor)

        results = store.index.search(vectors[0], top_k=1, score_fn=counting_scorer)

        assert results[0][0] == "0"
        assert scored < len(vectors) // 2


def test_schema_v1_is_migrated_and_backfilled_for_ann(tmp_path: Path) -> None:
    path = tmp_path / "v1.db"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE metadata_index (
            key TEXT PRIMARY KEY NOT NULL, kind TEXT NOT NULL,
            payload BLOB NOT NULL, dimension INTEGER NOT NULL, updated_at REAL NOT NULL
        );
        CREATE TABLE cold_archive (
            key TEXT PRIMARY KEY NOT NULL, payload BLOB NOT NULL, updated_at REAL NOT NULL
        );
        CREATE TABLE eviction_metadata (
            key TEXT PRIMARY KEY NOT NULL, metadata_json TEXT NOT NULL
        );
        PRAGMA user_version = 1;
        """
    )
    vector = np.array([1.0, 0.0])
    connection.execute(
        "INSERT INTO metadata_index VALUES (?, ?, ?, ?, ?)",
        ("legacy", "anchor", vector.tobytes(), 2, time.time()),
    )
    connection.commit()
    connection.close()

    with SQLiteStore(path) as store:
        assert store.index.search(vector, top_k=1) == [("legacy", 1.0)]
        version_row = store._connection.execute("PRAGMA user_version").fetchone()
        assert version_row is not None and version_row[0] == 2
