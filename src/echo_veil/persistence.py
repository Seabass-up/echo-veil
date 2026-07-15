"""Durable, transactional L2/L3 storage for Echo Veil.

``SQLiteStore`` coordinates the active workspace, Metadata Index, and Cold Archive in one SQLite
database. Evictions are committed with ``BEGIN IMMEDIATE`` so an L2 entry and
its L3 payload become visible together or not at all. SQLite WAL mode provides
crash recovery and cross-process writer serialization for the local deployment
case without adding another runtime dependency.

The metadata index uses persisted random-projection LSH buckets for candidate
selection and exact shield-aware reranking, avoiding global row scans.
"""

from __future__ import annotations

import json
import math
import os
import sqlite3
import stat
import time
from collections.abc import Callable
from collections.abc import Mapping
from numbers import Real
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any

import numpy as np

from .archive import (
    INDEX_KINDS,
    EvictionRecord,
    IndexEntry,
    MetadataIndex,
)
from .ann import RandomProjectionLSH
from .crypto_shield import is_serializable_protected_payload, load_protected_vector
from .vectors import Vector, as_vector, cosine_similarity
from .vine import Vine, VineState

SCHEMA_VERSION = 2
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_METADATA_BYTES = 65_536


class SQLiteStore:
    """Coordinated durable backend for the L2 index and L3 archive.

    Parameters
    ----------
    path:
        Filesystem path to the SQLite database. ``":memory:"`` is supported for
        tests but is correctly reported as non-durable.
    protected_payload_loader:
        Reconstructs a protected index payload from archived bytes. The default
        supports ``AesGcmCryptoShield`` via ``ProtectedVector.from_json_bytes``.
        Custom shields should provide their own loader.
    timeout_seconds:
        How long SQLite waits for another process's write transaction.
    verify_integrity:
        Run ``PRAGMA quick_check`` when opening the database.
    """

    backend_name = "SQLite transactional L2/L3 store"
    transactional = True
    database_path: str
    durable: bool
    cross_process_safe: bool
    index: SQLiteMetadataIndex
    archive: SQLiteColdArchive
    _loader: Callable[[bytes], object]
    _lock: RLock
    _closed: bool
    _connection: sqlite3.Connection
    _lsh: RandomProjectionLSH

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        protected_payload_loader: Callable[[bytes], object] | None = None,
        timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
        verify_integrity: bool = True,
    ) -> None:
        if isinstance(timeout_seconds, bool) or not isinstance(timeout_seconds, Real):
            raise TypeError("timeout_seconds must be a finite positive number")
        timeout = float(timeout_seconds)
        if not math.isfinite(timeout) or timeout <= 0.0:
            raise ValueError("timeout_seconds must be a finite positive number")
        if not isinstance(verify_integrity, bool):
            raise TypeError("verify_integrity must be a bool")
        if protected_payload_loader is not None and not callable(
            protected_payload_loader
        ):
            raise TypeError("protected_payload_loader must be callable")

        database_path, durable = self._prepare_path(path)
        self.database_path = database_path
        self.durable = durable
        self.cross_process_safe = durable
        self._loader = protected_payload_loader or load_protected_vector
        self._lsh = RandomProjectionLSH()
        self._lock = RLock()
        self._closed = False
        if durable:
            self._secure_database_file(database_path)
        self._connection = sqlite3.connect(
            database_path,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )

        try:
            self._configure_connection(timeout)
            self._initialize_schema()
            if verify_integrity:
                self.verify_integrity()
        except Exception:
            self._connection.close()
            self._closed = True
            raise

        self.index = SQLiteMetadataIndex(self)
        self.archive = SQLiteColdArchive(self)

    @staticmethod
    def _prepare_path(path: str | os.PathLike[str]) -> tuple[str, bool]:
        try:
            raw_path = os.fspath(path)
        except TypeError as exc:
            raise TypeError("path must be a filesystem path") from exc
        if not isinstance(raw_path, str) or not raw_path.strip():
            raise ValueError("path must be a non-empty filesystem path")
        if raw_path == ":memory:":
            return raw_path, False
        if raw_path.startswith("file:"):
            raise ValueError("SQLite URI paths are not supported")

        candidate = Path(raw_path).expanduser()
        if candidate.exists() and candidate.is_symlink():
            raise ValueError("database path must not be a symbolic link")
        if candidate.exists() and not candidate.is_file():
            raise ValueError("database path must reference a regular file")
        candidate.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        return str(candidate.absolute()), True

    @staticmethod
    def _secure_database_file(database_path: str) -> None:
        flags = os.O_RDWR | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(database_path, flags, 0o600)
        try:
            info = os.fstat(descriptor)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("database path must reference a regular file")
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            else:
                os.chmod(database_path, stat.S_IREAD | stat.S_IWRITE)
        finally:
            os.close(descriptor)

    def _configure_connection(self, timeout_seconds: float) -> None:
        timeout_ms = max(1, int(timeout_seconds * 1_000))
        self._connection.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute(
            """
            CREATE TEMP TABLE IF NOT EXISTS query_ann_buckets (
                band INTEGER NOT NULL,
                bucket INTEGER NOT NULL,
                PRIMARY KEY(band, bucket)
            ) WITHOUT ROWID
            """
        )
        if self.durable:
            journal_mode = self._connection.execute(
                "PRAGMA journal_mode = WAL"
            ).fetchone()
            if journal_mode is None or str(journal_mode[0]).lower() != "wal":
                raise RuntimeError("SQLite WAL mode could not be enabled")

    def _initialize_schema(self) -> None:
        with self._lock:
            version_row = self._connection.execute("PRAGMA user_version").fetchone()
            version = int(version_row[0]) if version_row is not None else 0
            if version not in {0, 1, SCHEMA_VERSION}:
                raise RuntimeError(
                    f"unsupported Echo Veil SQLite schema version: {version}"
                )
            self._begin_locked()
            try:
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS metadata_index (
                        key TEXT PRIMARY KEY NOT NULL,
                        kind TEXT NOT NULL CHECK (
                            kind IN ('anchor', 'fossil', 'protected_anchor')
                        ),
                        payload BLOB NOT NULL CHECK (length(payload) > 0),
                        dimension INTEGER NOT NULL CHECK (dimension > 0),
                        updated_at REAL NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS ann_buckets (
                        key TEXT NOT NULL,
                        band INTEGER NOT NULL CHECK (band >= 0),
                        bucket INTEGER NOT NULL CHECK (bucket >= 0),
                        PRIMARY KEY(key, band),
                        FOREIGN KEY(key) REFERENCES metadata_index(key)
                            ON DELETE CASCADE
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS active_workspace (
                        key TEXT PRIMARY KEY NOT NULL,
                        topic TEXT NOT NULL,
                        created_at REAL NOT NULL,
                        last_touched REAL NOT NULL,
                        state TEXT NOT NULL CHECK (state IN ('active', 'twilight')),
                        locked INTEGER NOT NULL CHECK (locked IN (0, 1)),
                        score REAL NOT NULL,
                        twilight_since REAL,
                        payload_kind TEXT NOT NULL CHECK (
                            payload_kind IN ('plain', 'compressed', 'protected')
                        ),
                        payload BLOB NOT NULL CHECK (length(payload) > 0),
                        dimension INTEGER NOT NULL CHECK (dimension > 0),
                        twilight_cycles INTEGER NOT NULL CHECK (twilight_cycles >= 0),
                        crest_rank INTEGER CHECK (crest_rank BETWEEN 0 AND 2)
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS cold_archive (
                        key TEXT PRIMARY KEY NOT NULL,
                        payload BLOB NOT NULL CHECK (length(payload) > 0),
                        updated_at REAL NOT NULL
                    )
                    """
                )
                self._connection.execute(
                    """
                    CREATE TABLE IF NOT EXISTS eviction_metadata (
                        key TEXT PRIMARY KEY NOT NULL,
                        metadata_json TEXT NOT NULL,
                        FOREIGN KEY(key) REFERENCES metadata_index(key)
                            ON DELETE CASCADE
                    )
                    """
                )
                self._validate_schema_locked()
                self._connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_metadata_kind "
                    "ON metadata_index(kind)"
                )
                self._connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_ann_lookup "
                    "ON ann_buckets(band, bucket, key)"
                )
                if version == 1:
                    self._backfill_ann_locked()
                self._connection.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def _validate_schema_locked(self) -> None:
        expected_columns = {
            "metadata_index": (
                "key",
                "kind",
                "payload",
                "dimension",
                "updated_at",
            ),
            "cold_archive": ("key", "payload", "updated_at"),
            "eviction_metadata": ("key", "metadata_json"),
            "ann_buckets": ("key", "band", "bucket"),
            "active_workspace": (
                "key",
                "topic",
                "created_at",
                "last_touched",
                "state",
                "locked",
                "score",
                "twilight_since",
                "payload_kind",
                "payload",
                "dimension",
                "twilight_cycles",
                "crest_rank",
            ),
        }
        for table, expected in expected_columns.items():
            rows = self._connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual = tuple(str(row[1]) for row in rows)
            if actual != expected:
                raise RuntimeError(
                    f"SQLite schema mismatch for {table}: "
                    f"expected {expected}, got {actual}"
                )

    def verify_integrity(self) -> None:
        """Raise if SQLite reports any structural database corruption."""
        with self._lock:
            self._ensure_open_locked()
            rows = self._connection.execute("PRAGMA quick_check").fetchall()
        results = tuple(str(row[0]) for row in rows)
        if results != ("ok",):
            raise RuntimeError("SQLite integrity check failed: " + "; ".join(results))

    def commit_evictions(self, records: list[EvictionRecord]) -> None:
        """Atomically commit matching L2 and L3 records for all evictions."""
        if not isinstance(records, list):
            raise TypeError("records must be a list of EvictionRecord objects")
        if not records:
            return
        if not all(isinstance(record, EvictionRecord) for record in records):
            raise TypeError("records must contain only EvictionRecord objects")
        keys = [record.key for record in records]
        if len(keys) != len(set(keys)):
            raise ValueError("eviction records must have unique keys")
        prepared = [self._prepare_eviction(record) for record in records]

        with self._lock:
            self._ensure_open_locked()
            self._begin_locked()
            try:
                for (
                    key,
                    kind,
                    index_payload,
                    archive_payload,
                    dimension,
                    metadata_json,
                    signatures,
                ) in prepared:
                    self._put_archive_locked(key, archive_payload)
                    self._upsert_metadata_locked(
                        key,
                        kind,
                        index_payload,
                        dimension,
                    )
                    self._replace_ann_buckets_locked(key, signatures)
                    self._put_eviction_metadata_locked(key, metadata_json)
                    self._connection.execute(
                        "DELETE FROM active_workspace WHERE key = ?", (key,)
                    )
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def _prepare_eviction(
        self,
        record: EvictionRecord,
    ) -> tuple[str, str, bytes, bytes, int, str, tuple[tuple[int, int], ...]]:
        MetadataIndex._validate_key(record.key)
        self._validate_kind(record.kind)
        dimension = self._validate_dimension(record.dimension)
        archive_payload = self._validate_payload(record.archive_payload, "archive")
        if record.kind == "protected_anchor":
            index_payload = archive_payload
            # Fail before opening a transaction if the configured loader cannot
            # reconstruct this shield's persisted payload.
            self._decode_index_entry(
                record.key,
                record.kind,
                index_payload,
                dimension,
            )
        else:
            anchor = as_vector(
                record.anchor,
                allow_empty=False,
                name="eviction index anchor",
            )
            if anchor.size != dimension:
                raise ValueError(
                    f"dimension mismatch: expected ({dimension},), got {anchor.shape}"
                )
            index_payload = anchor.astype(np.float64, copy=False).tobytes(order="C")
        hint = record.index_hint
        if hint is None and record.kind != "protected_anchor":
            hint = anchor
        signatures = () if hint is None else self._lsh.signatures(hint)
        metadata_json = self._encode_metadata(record.metadata)
        return (
            record.key,
            record.kind,
            index_payload,
            archive_payload,
            dimension,
            metadata_json,
            signatures,
        )

    def _upsert_index(self, key: str, anchor: Any, kind: str) -> None:
        MetadataIndex._validate_key(key)
        self._validate_kind(kind)
        payload, dimension = self._encode_index_anchor(anchor, kind)
        signatures = (
            ()
            if kind == "protected_anchor"
            else self._lsh.signatures(
                as_vector(anchor, allow_empty=False, name="index anchor")
            )
        )
        with self._lock:
            self._ensure_open_locked()
            self._begin_locked()
            try:
                self._upsert_metadata_locked(key, kind, payload, dimension)
                self._replace_ann_buckets_locked(key, signatures)
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def _remove_index(self, key: str) -> None:
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            self._connection.execute("DELETE FROM metadata_index WHERE key = ?", (key,))

    def _index_rows(self, query: Vector) -> list[tuple[str, str, bytes, int]]:
        signatures = self._lsh.signatures(query)
        with self._lock:
            self._ensure_open_locked()
            self._connection.execute("DELETE FROM query_ann_buckets")
            self._connection.executemany(
                "INSERT INTO query_ann_buckets(band, bucket) VALUES (?, ?)",
                signatures,
            )
            rows = self._connection.execute(
                "SELECT DISTINCT m.key, m.kind, m.payload, m.dimension "
                "FROM metadata_index AS m "
                "LEFT JOIN ann_buckets AS b ON b.key = m.key "
                "LEFT JOIN query_ann_buckets AS q "
                "ON q.band = b.band AND q.bucket = b.bucket "
                "WHERE q.band IS NOT NULL OR NOT EXISTS ("
                "SELECT 1 FROM ann_buckets AS missing WHERE missing.key = m.key"
                ") ORDER BY m.key",
            ).fetchall()
        return [
            (str(key), str(kind), bytes(payload), int(dimension))
            for key, kind, payload, dimension in rows
        ]

    def _backfill_ann_locked(self) -> None:
        rows = self._connection.execute(
            "SELECT key, payload, dimension FROM metadata_index "
            "WHERE kind IN ('anchor', 'fossil')"
        ).fetchall()
        for key, payload, dimension in rows:
            expected = int(dimension) * np.dtype(np.float64).itemsize
            raw = bytes(payload)
            if len(raw) != expected:
                raise RuntimeError("cannot migrate malformed index vector")
            vector = np.frombuffer(raw, dtype=np.float64).copy()
            self._replace_ann_buckets_locked(str(key), self._lsh.signatures(vector))

    def _replace_ann_buckets_locked(
        self,
        key: str,
        signatures: tuple[tuple[int, int], ...],
    ) -> None:
        self._connection.execute("DELETE FROM ann_buckets WHERE key = ?", (key,))
        self._connection.executemany(
            "INSERT INTO ann_buckets(key, band, bucket) VALUES (?, ?, ?)",
            ((key, band, bucket) for band, bucket in signatures),
        )

    def _index_dimension(self) -> int | None:
        with self._lock:
            self._ensure_open_locked()
            rows = self._connection.execute(
                "SELECT DISTINCT dimension FROM metadata_index LIMIT 2"
            ).fetchall()
        if not rows:
            return None
        if len(rows) != 1:
            raise RuntimeError("metadata index contains inconsistent dimensions")
        return self._validate_dimension(int(rows[0][0]))

    def _index_length(self) -> int:
        return self._table_length("metadata_index")

    def _put_archive(self, key: str, payload: bytes) -> None:
        MetadataIndex._validate_key(key)
        validated = self._validate_payload(payload, "archive")
        with self._lock:
            self._ensure_open_locked()
            self._connection.execute(
                """
                INSERT INTO cold_archive(key, payload, updated_at)
                VALUES (?, ?, ?)
                ON CONFLICT(key) DO UPDATE SET
                    payload = excluded.payload,
                    updated_at = excluded.updated_at
                """,
                (key, validated, time.time()),
            )

    def _get_archive(self, key: str) -> bytes | None:
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            row = self._connection.execute(
                "SELECT payload FROM cold_archive WHERE key = ?",
                (key,),
            ).fetchone()
        return None if row is None else bytes(row[0])

    def _archive_length(self) -> int:
        return self._table_length("cold_archive")

    def get_eviction_metadata(self, key: str) -> dict[str, object] | None:
        """Return durable lifecycle/topic metadata for an evicted vine."""
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            row = self._connection.execute(
                "SELECT metadata_json FROM eviction_metadata WHERE key = ?",
                (key,),
            ).fetchone()
        if row is None:
            return None
        try:
            decoded = json.loads(str(row[0]))
        except (TypeError, ValueError, json.JSONDecodeError) as exc:
            raise ValueError("persisted eviction metadata is invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("persisted eviction metadata must be an object")
        return decoded

    def save_workspace(
        self,
        vines: list[Vine],
        twilight_cycles: Mapping[str, int],
        crests: tuple[str, ...],
    ) -> None:
        """Atomically replace the durable L1 checkpoint."""
        if not isinstance(vines, list) or not all(
            isinstance(vine, Vine) for vine in vines
        ):
            raise TypeError("vines must be a list of Vine objects")
        if not isinstance(twilight_cycles, Mapping):
            raise TypeError("twilight_cycles must be a mapping")
        crest_ranks = {vine_id: rank for rank, vine_id in enumerate(crests)}
        prepared = [
            self._prepare_workspace_vine(
                vine,
                int(twilight_cycles.get(vine.vine_id, 0)),
                crest_ranks.get(vine.vine_id),
            )
            for vine in vines
            if vine.state != VineState.EVICTED
        ]
        with self._lock:
            self._ensure_open_locked()
            self._begin_locked()
            try:
                self._connection.execute("DELETE FROM active_workspace")
                self._connection.executemany(
                    """
                    INSERT INTO active_workspace(
                        key, topic, created_at, last_touched, state, locked,
                        score, twilight_since, payload_kind, payload, dimension,
                        twilight_cycles, crest_rank
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    prepared,
                )
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def load_workspace(self) -> tuple[list[Vine], dict[str, int], tuple[str, ...]]:
        """Load and validate the most recent durable L1 checkpoint."""
        with self._lock:
            self._ensure_open_locked()
            rows = self._connection.execute(
                """
                SELECT key, topic, created_at, last_touched, state, locked,
                       score, twilight_since, payload_kind, payload, dimension,
                       twilight_cycles, crest_rank
                FROM active_workspace ORDER BY key
                """
            ).fetchall()
        vines: list[Vine] = []
        cycles: dict[str, int] = {}
        ranked_crests: list[tuple[int, str]] = []
        for row in rows:
            vine, cycle_count, crest_rank = self._decode_workspace_vine(row)
            vines.append(vine)
            if cycle_count:
                cycles[vine.vine_id] = cycle_count
            if crest_rank is not None:
                ranked_crests.append((crest_rank, vine.vine_id))
        ranked_crests.sort()
        expected_ranks = list(range(len(ranked_crests)))
        if [rank for rank, _ in ranked_crests] != expected_ranks:
            raise ValueError("persisted focal crest ranks are invalid")
        return vines, cycles, tuple(vine_id for _, vine_id in ranked_crests)

    def _prepare_workspace_vine(
        self,
        vine: Vine,
        twilight_cycles: int,
        crest_rank: int | None,
    ) -> tuple[object, ...]:
        if twilight_cycles < 0:
            raise ValueError("twilight cycle count must be non-negative")
        if vine.protected_anchor is not None:
            payload_kind = "protected"
            if not is_serializable_protected_payload(vine.protected_anchor):
                raise TypeError("protected workspace anchors must be serializable")
            payload = self._validate_payload(
                vine.protected_anchor.to_json_bytes(), "workspace"
            )
            shape = getattr(vine.protected_anchor, "shape", None)
            if not isinstance(shape, tuple) or len(shape) != 1:
                raise ValueError("protected workspace anchor has invalid shape")
            dimension = self._validate_dimension(shape[0])
        elif vine._compressed is not None:
            payload_kind = "compressed"
            payload = self._validate_payload(vine._compressed, "workspace")
            if vine._anchor_shape is None or len(vine._anchor_shape) != 1:
                raise ValueError("compressed workspace anchor has invalid shape")
            dimension = self._validate_dimension(vine._anchor_shape[0])
        else:
            payload_kind = "plain"
            anchor = as_vector(vine.anchor, allow_empty=False, name="workspace anchor")
            payload = anchor.astype(np.float64, copy=False).tobytes(order="C")
            dimension = anchor.size
        return (
            vine.vine_id,
            vine.topic,
            vine.created_at,
            vine.last_touched,
            vine.state.value,
            int(vine.locked),
            vine.score,
            vine.twilight_since,
            payload_kind,
            payload,
            dimension,
            twilight_cycles,
            crest_rank,
        )

    def _decode_workspace_vine(
        self, row: tuple[Any, ...]
    ) -> tuple[Vine, int, int | None]:
        (
            key,
            topic,
            created_at,
            last_touched,
            state,
            locked,
            score,
            twilight_since,
            payload_kind,
            payload,
            dimension,
            cycle_count,
            crest_rank,
        ) = row
        dimension = self._validate_dimension(int(dimension))
        raw = self._validate_payload(payload, "workspace")
        protected: object | None = None
        anchor = np.zeros(0, dtype=np.float64)
        compressed: bytes | None = None
        if payload_kind == "protected":
            protected = self._loader(raw)
            if getattr(protected, "shape", None) != (dimension,):
                raise ValueError("protected workspace dimension mismatch")
        elif payload_kind == "compressed":
            compressed = raw
        elif payload_kind == "plain":
            if len(raw) != dimension * np.dtype(np.float64).itemsize:
                raise ValueError("plain workspace payload size mismatch")
            anchor = np.frombuffer(raw, dtype=np.float64).copy()
        else:
            raise ValueError("unknown persisted workspace payload kind")
        vine = Vine(
            topic=str(topic),
            anchor=anchor,
            vine_id=str(key),
            created_at=float(created_at),
            last_touched=float(last_touched),
            state=VineState(str(state)),
            locked=bool(locked),
            score=float(score),
            twilight_since=None if twilight_since is None else float(twilight_since),
            protected_anchor=protected,
        )
        if compressed is not None:
            vine._compressed = compressed
            vine._anchor_shape = (dimension,)
        rank = None if crest_rank is None else int(crest_rank)
        return vine, int(cycle_count), rank

    def _table_length(self, table: str) -> int:
        if table == "metadata_index":
            query = "SELECT COUNT(*) FROM metadata_index"
        elif table == "cold_archive":
            query = "SELECT COUNT(*) FROM cold_archive"
        else:
            raise ValueError("unsupported table")
        with self._lock:
            self._ensure_open_locked()
            row = self._connection.execute(query).fetchone()
        if row is None:
            raise RuntimeError("SQLite count query returned no result")
        return int(row[0])

    def _decode_index_entry(
        self,
        key: str,
        kind: str,
        payload: bytes,
        dimension: int,
    ) -> IndexEntry:
        MetadataIndex._validate_key(key)
        self._validate_kind(kind)
        dimension = self._validate_dimension(dimension)
        payload = self._validate_payload(payload, "index")
        if kind == "protected_anchor":
            anchor = self._loader(payload)
            shape = getattr(anchor, "shape", None)
            if shape is not None and shape != (dimension,):
                raise ValueError(
                    "protected index payload dimension does not match metadata"
                )
        else:
            expected_bytes = dimension * np.dtype(np.float64).itemsize
            if len(payload) != expected_bytes:
                raise ValueError("index payload size does not match metadata")
            restored = np.frombuffer(payload, dtype=np.float64).copy()
            anchor = as_vector(
                restored,
                allow_empty=False,
                name="persisted index anchor",
            )
        return IndexEntry(key=key, anchor=anchor, kind=kind)

    def _encode_index_anchor(self, anchor: Any, kind: str) -> tuple[bytes, int]:
        if kind == "protected_anchor":
            if not is_serializable_protected_payload(anchor):
                raise TypeError(
                    "protected index anchors must implement to_json_bytes()"
                )
            payload = self._validate_payload(anchor.to_json_bytes(), "index")
            shape = getattr(anchor, "shape", None)
            if (
                not isinstance(shape, tuple)
                or len(shape) != 1
                or isinstance(shape[0], bool)
                or not isinstance(shape[0], int)
            ):
                raise ValueError("protected index anchor must expose a 1-D shape")
            return payload, self._validate_dimension(shape[0])

        vector = as_vector(
            anchor,
            allow_empty=False,
            name="index anchor",
        )
        return (
            vector.astype(np.float64, copy=False).tobytes(order="C"),
            vector.size,
        )

    def _upsert_metadata_locked(
        self,
        key: str,
        kind: str,
        payload: bytes,
        dimension: int,
    ) -> None:
        conflicting_rows = self._connection.execute(
            "SELECT DISTINCT dimension FROM metadata_index WHERE key <> ? LIMIT 2",
            (key,),
        ).fetchall()
        if len(conflicting_rows) > 1:
            raise RuntimeError("metadata index contains inconsistent dimensions")
        if conflicting_rows and int(conflicting_rows[0][0]) != dimension:
            raise ValueError(
                f"dimension mismatch: expected ({int(conflicting_rows[0][0])},), "
                f"got ({dimension},)"
            )
        self._connection.execute(
            """
            INSERT INTO metadata_index(key, kind, payload, dimension, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                kind = excluded.kind,
                payload = excluded.payload,
                dimension = excluded.dimension,
                updated_at = excluded.updated_at
            """,
            (key, kind, payload, dimension, time.time()),
        )

    def _put_archive_locked(self, key: str, payload: bytes) -> None:
        self._connection.execute(
            """
            INSERT INTO cold_archive(key, payload, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET
                payload = excluded.payload,
                updated_at = excluded.updated_at
            """,
            (key, payload, time.time()),
        )

    def _put_eviction_metadata_locked(self, key: str, metadata_json: str) -> None:
        self._connection.execute(
            """
            INSERT INTO eviction_metadata(key, metadata_json)
            VALUES (?, ?)
            ON CONFLICT(key) DO UPDATE SET
                metadata_json = excluded.metadata_json
            """,
            (key, metadata_json),
        )

    def _begin_locked(self) -> None:
        self._ensure_open_locked()
        self._connection.execute("BEGIN IMMEDIATE")

    def _commit_locked(self) -> None:
        self._connection.execute("COMMIT")

    def _rollback_locked(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")

    def _ensure_open_locked(self) -> None:
        if self._closed:
            raise RuntimeError("SQLiteStore is closed")

    @staticmethod
    def _validate_kind(kind: str) -> None:
        if not isinstance(kind, str) or kind not in INDEX_KINDS:
            raise ValueError(f"unsupported index entry kind: {kind!r}")

    @staticmethod
    def _validate_dimension(dimension: int) -> int:
        if isinstance(dimension, bool) or not isinstance(dimension, int):
            raise TypeError("dimension must be a positive integer")
        if dimension <= 0:
            raise ValueError("dimension must be a positive integer")
        return dimension

    @staticmethod
    def _validate_payload(payload: object, name: str) -> bytes:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TypeError(f"{name} payload must be bytes-like")
        result = bytes(payload)
        if not result:
            raise ValueError(f"{name} payload must not be empty")
        return result

    @staticmethod
    def _encode_metadata(metadata: Mapping[str, object]) -> str:
        if not isinstance(metadata, Mapping):
            raise TypeError("eviction metadata must be a mapping")
        try:
            encoded = json.dumps(
                dict(metadata),
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("eviction metadata must be JSON-serializable") from exc
        if len(encoded.encode("utf-8")) > MAX_METADATA_BYTES:
            raise ValueError(
                f"eviction metadata exceeds the {MAX_METADATA_BYTES}-byte limit"
            )
        return encoded

    def close(self) -> None:
        """Checkpoint and close the database connection. Idempotent."""
        with self._lock:
            if self._closed:
                return
            if self.durable:
                self._connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            self._connection.close()
            self._closed = True

    def __enter__(self) -> SQLiteStore:
        with self._lock:
            self._ensure_open_locked()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class SQLiteMetadataIndex:
    """Persistent L2 view backed by ``SQLiteStore``."""

    backend_name = "SQLite durable metadata index"
    transactional = True
    search_strategy = "lsh-ann"

    def __init__(self, store: SQLiteStore) -> None:
        self._store = store
        self.durable = store.durable
        self.cross_process_safe = store.cross_process_safe

    @property
    def dimension(self) -> int | None:
        return self._store._index_dimension()

    def upsert(self, key: str, anchor: Any, kind: str = "anchor") -> None:
        self._store._upsert_index(key, anchor, kind)

    def remove(self, key: str) -> None:
        self._store._remove_index(key)

    def search(
        self,
        query: Vector,
        top_k: int = 5,
        score_fn: Callable[[Vector, IndexEntry], float] | None = None,
    ) -> list[tuple[str, float]]:
        if isinstance(top_k, bool) or not isinstance(top_k, int):
            raise TypeError("top_k must be a non-negative integer")
        if top_k < 0:
            raise ValueError("top_k must be a non-negative integer")
        query_vector = as_vector(
            query,
            allow_empty=False,
            name="query vector",
        )
        dimension = self.dimension
        if dimension is not None and query_vector.size != dimension:
            raise ValueError(
                f"dimension mismatch: expected ({dimension},), got {query_vector.shape}"
            )

        rows = self._store._index_rows(query_vector)
        entries = [self._store._decode_index_entry(*row) for row in rows]
        if score_fn is None and any(
            entry.kind == "protected_anchor" for entry in entries
        ):
            raise TypeError("protected index entries require a shield-aware score_fn")

        scored: list[tuple[str, float]] = []
        for entry in entries:
            raw_score = (
                score_fn(query_vector, entry)
                if score_fn is not None
                else cosine_similarity(query_vector, entry.anchor)
            )
            if isinstance(raw_score, bool) or not isinstance(raw_score, Real):
                raise TypeError("index scorer must return a finite number")
            score = float(raw_score)
            if not math.isfinite(score):
                raise ValueError("index scorer must return a finite number")
            scored.append((entry.key, score))
        scored.sort(key=lambda item: item[1], reverse=True)
        return scored[:top_k]

    def __len__(self) -> int:
        return self._store._index_length()


class SQLiteColdArchive:
    """Persistent L3 view backed by ``SQLiteStore``."""

    backend_name = "SQLite durable cold archive"
    transactional = True

    def __init__(self, store: SQLiteStore) -> None:
        self._store = store
        self.durable = store.durable
        self.cross_process_safe = store.cross_process_safe

    def put(self, key: str, payload: bytes) -> None:
        self._store._put_archive(key, payload)

    def get(self, key: str) -> bytes | None:
        return self._store._get_archive(key)

    def __len__(self) -> int:
        return self._store._archive_length()
