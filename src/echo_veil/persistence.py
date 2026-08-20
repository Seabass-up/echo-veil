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

import hashlib
import hmac
import json
import math
import os
import sqlite3
import time
from collections.abc import Callable
from collections.abc import Mapping
from numbers import Real
from pathlib import Path
from threading import RLock
from types import TracebackType
from typing import Any

import numpy as np

from ._json import strict_json_loads
from .agent_security import (
    _posix_identity,
    _posix_open_private_file,
    _secure_directory as _secure_profile_directory,
    _windows_create_private_staging,
    _windows_ensure_private_directory,
    _windows_expected_private_security,
    _windows_open_private_file,
    _windows_pinned_directory_chain,
    _windows_verify_descriptor,
    _windows_verify_private_directory,
    _windows_verify_private_sqlite_sidecars,
)
from .archive import (
    INDEX_KINDS,
    EvictionRecord,
    IndexEntry,
    MetadataIndex,
)
from .ann import (
    LSH_INDEX_DERIVATION_VERSION,
    RandomProjectionLSH,
)
from .crypto_shield import is_serializable_protected_payload, load_protected_vector
from .vectors import Vector, as_vector, cosine_similarity
from .vine import Vine, VineState

SCHEMA_VERSION = 4
DEFAULT_TIMEOUT_SECONDS = 5.0
MAX_METADATA_BYTES = 65_536
LSH_INDEX_SCHEMA = "echo-veil-lsh-index-v2"
MAX_INDEX_BATCH_SIZE = 1_000


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
    _lsh_key_custody: str
    _protected_index_hint: Callable[[object], Vector] | None
    _workspace_generation: int
    _transaction_generation: int | None

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        protected_payload_loader: Callable[[bytes], object] | None = None,
        lsh_key: bytes | None = None,
        protected_index_hint: Callable[[object], Vector] | None = None,
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
        if lsh_key is not None and (
            not isinstance(lsh_key, bytes) or len(lsh_key) != 32
        ):
            raise ValueError("lsh_key must contain exactly 32 bytes")
        if protected_index_hint is not None and not callable(protected_index_hint):
            raise TypeError("protected_index_hint must be callable")

        database_path, durable = self._prepare_path(path)
        self.database_path = database_path
        self.durable = durable
        self.cross_process_safe = durable
        self._loader = protected_payload_loader or load_protected_vector
        if lsh_key is None:
            identity = (
                os.urandom(32)
                if not durable
                else database_path.encode("utf-8", errors="strict")
            )
            lsh_key = hashlib.sha256(
                b"echo-veil-development-lsh-path-key-v2\0" + identity
            ).digest()
            self._lsh_key_custody = "path-derived-development"
        else:
            self._lsh_key_custody = "profile-derived"
        self._lsh = RandomProjectionLSH(lsh_key)
        self._protected_index_hint = protected_index_hint
        self._lock = RLock()
        self._closed = False
        self._workspace_generation = 0
        self._transaction_generation = None
        database_identity = (
            self._secure_database_file(database_path) if durable else None
        )
        self._connection = sqlite3.connect(
            database_path,
            timeout=timeout,
            isolation_level=None,
            check_same_thread=False,
        )

        try:
            if durable:
                self._verify_database_files(database_path, database_identity)
            self._configure_connection(timeout)
            if durable:
                self._verify_database_files(database_path, database_identity)
            self._initialize_schema()
            self._workspace_generation = self._read_generation_locked()
            if verify_integrity:
                self.verify_integrity()
            if durable:
                self._verify_database_files(database_path, database_identity)
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
        absolute_candidate = candidate.absolute()
        if any(
            component.is_symlink()
            for component in (absolute_candidate, *absolute_candidate.parents)
        ):
            raise ValueError("database path must not contain symbolic links")
        if candidate.exists() and not candidate.is_file():
            raise ValueError("database path must reference a regular file")
        if os.name == "nt":
            _windows_ensure_private_directory(
                absolute_candidate.parent,
                harden_existing=False,
            )
        else:
            _secure_profile_directory(absolute_candidate.parent)
        return str(absolute_candidate), True

    @staticmethod
    def _secure_database_file(database_path: str) -> tuple[int, int, int] | None:
        path = Path(database_path)
        if os.name == "nt":
            _windows_ensure_private_directory(
                path.parent,
                harden_existing=False,
            )
            with _windows_pinned_directory_chain(path.parent):
                _windows_verify_private_directory(path.parent)
                try:
                    descriptor, state = _windows_create_private_staging(path)
                except FileExistsError:
                    descriptor = _windows_open_private_file(
                        path,
                        writable=False,
                        share_write=True,
                    )
                    state = None
                try:
                    _windows_verify_descriptor(
                        descriptor,
                        path,
                        expected_payload=None,
                        expected_state=state,
                        expected_security=(
                            None
                            if state is not None
                            else _windows_expected_private_security()
                        ),
                    )
                finally:
                    os.close(descriptor)
            _windows_verify_private_sqlite_sidecars(path)
            return None
        _secure_profile_directory(path.parent)
        try:
            with _posix_open_private_file(
                path,
                os.O_RDWR | os.O_CREAT,
                label="SQLite database",
            ) as descriptor:
                return _posix_identity(os.fstat(descriptor))
        except OSError as exc:
            raise ValueError(
                "database file permissions, ownership, or identity are unsafe"
            ) from exc

    @staticmethod
    def _verify_database_files(
        database_path: str,
        expected_identity: tuple[int, int, int] | None,
    ) -> None:
        path = Path(database_path)
        if os.name == "nt":
            SQLiteStore._secure_database_file(database_path)
            return
        try:
            with _posix_open_private_file(
                path,
                os.O_RDWR,
                label="SQLite database",
            ) as descriptor:
                current_identity = _posix_identity(os.fstat(descriptor))
                if (
                    expected_identity is not None
                    and current_identity != expected_identity
                ):
                    raise OSError("SQLite database identity changed during open")
            for suffix in ("-wal", "-shm"):
                sidecar = Path(f"{database_path}{suffix}")
                try:
                    with _posix_open_private_file(
                        sidecar,
                        os.O_RDWR,
                        label=f"SQLite {suffix[1:]} sidecar",
                    ):
                        pass
                except FileNotFoundError:
                    continue
        except OSError as exc:
            raise ValueError(
                "database files changed identity or have unsafe access"
            ) from exc

    def _configure_connection(self, timeout_seconds: float) -> None:
        timeout_ms = max(1, int(timeout_seconds * 1_000))
        self._connection.execute(f"PRAGMA busy_timeout = {timeout_ms}")
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA secure_delete = ON")
        self._connection.execute("PRAGMA trusted_schema = OFF")
        self._connection.execute("PRAGMA synchronous = FULL")
        self._connection.execute(
            """
            CREATE TEMP TABLE IF NOT EXISTS query_ann_buckets (
                band INTEGER NOT NULL,
                bucket BLOB NOT NULL CHECK(length(bucket) = 32),
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
            if version not in {0, 1, 2, 3, SCHEMA_VERSION}:
                raise RuntimeError(
                    f"unsupported Echo Veil SQLite schema version: {version}"
                )
            self._begin_locked(advance_generation=False)
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
                    CREATE TABLE IF NOT EXISTS workspace_generation (
                        singleton INTEGER PRIMARY KEY NOT NULL
                            CHECK(singleton = 1),
                        generation INTEGER NOT NULL CHECK(generation >= 0)
                    )
                    """
                )
                self._connection.execute(
                    """
                    INSERT INTO workspace_generation(singleton, generation)
                    VALUES (1, 0)
                    ON CONFLICT(singleton) DO NOTHING
                    """
                )
                if version < SCHEMA_VERSION:
                    self._connection.execute("DROP INDEX IF EXISTS idx_ann_lookup")
                    self._connection.execute("DROP TABLE IF EXISTS ann_buckets")
                    self._connection.execute(
                        """
                        CREATE TABLE ann_buckets (
                            key TEXT NOT NULL,
                            band INTEGER NOT NULL CHECK (band >= 0),
                            bucket BLOB NOT NULL CHECK(length(bucket) = 32),
                            auth_tag BLOB NOT NULL CHECK(length(auth_tag) = 32),
                            PRIMARY KEY(key, band),
                            FOREIGN KEY(key) REFERENCES metadata_index(key)
                                ON DELETE CASCADE
                        )
                        """
                    )
                    self._connection.execute(
                        """
                        CREATE TABLE ann_config (
                            singleton INTEGER PRIMARY KEY NOT NULL
                                CHECK(singleton = 1),
                            schema TEXT NOT NULL,
                            derivation_version INTEGER NOT NULL,
                            key_fingerprint TEXT NOT NULL
                                CHECK(length(key_fingerprint) = 64),
                            bands INTEGER NOT NULL CHECK(bands > 0),
                            bits_per_band INTEGER NOT NULL
                                CHECK(bits_per_band > 0)
                        )
                        """
                    )
                    self._connection.execute(
                        """
                        INSERT INTO ann_config(
                            singleton, schema, derivation_version,
                            key_fingerprint, bands, bits_per_band
                        ) VALUES (1, ?, ?, ?, ?, ?)
                        """,
                        (
                            LSH_INDEX_SCHEMA,
                            LSH_INDEX_DERIVATION_VERSION,
                            self._lsh.key_fingerprint,
                            self._lsh.config.bands,
                            self._lsh.config.bits_per_band,
                        ),
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
                    self._migrate_v1_eviction_metadata_locked()
                self._validate_schema_objects_locked()
                if version < SCHEMA_VERSION:
                    self._backfill_ann_locked()
                else:
                    self._reconcile_lsh_key_locked()
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
            "ann_buckets": ("key", "band", "bucket", "auth_tag"),
            "ann_config": (
                "singleton",
                "schema",
                "derivation_version",
                "key_fingerprint",
                "bands",
                "bits_per_band",
            ),
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
            "workspace_generation": ("singleton", "generation"),
        }
        for table, expected in expected_columns.items():
            rows = self._connection.execute(f"PRAGMA table_info({table})").fetchall()
            actual = tuple(str(row[1]) for row in rows)
            if actual != expected:
                raise RuntimeError("SQLite schema mismatch")

    def _migrate_v1_eviction_metadata_locked(self) -> None:
        expected = (("metadata_index", "key", "key", "NO ACTION", "CASCADE"),)
        actual = tuple(
            (
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                str(row[6]),
            )
            for row in self._connection.execute(
                "PRAGMA foreign_key_list(eviction_metadata)"
            )
        )
        if actual == expected:
            return
        if actual:
            raise RuntimeError("SQLite schema foreign-key mismatch")
        self._connection.execute(
            "ALTER TABLE eviction_metadata RENAME TO eviction_metadata_v1"
        )
        self._connection.execute(
            """
            CREATE TABLE eviction_metadata (
                key TEXT PRIMARY KEY NOT NULL,
                metadata_json TEXT NOT NULL,
                FOREIGN KEY(key) REFERENCES metadata_index(key)
                    ON DELETE CASCADE
            )
            """
        )
        self._connection.execute(
            """
            INSERT INTO eviction_metadata(key, metadata_json)
            SELECT key, metadata_json FROM eviction_metadata_v1
            """
        )
        self._connection.execute("DROP TABLE eviction_metadata_v1")

    def _validate_schema_objects_locked(self) -> None:
        tables = {
            "metadata_index",
            "ann_buckets",
            "ann_config",
            "active_workspace",
            "cold_archive",
            "eviction_metadata",
            "workspace_generation",
        }
        expected_objects = {
            *(("table", table, table) for table in tables),
            ("index", "idx_metadata_kind", "metadata_index"),
            ("index", "idx_ann_lookup", "ann_buckets"),
        }
        actual_objects = {
            (str(row[0]), str(row[1]), str(row[2]))
            for row in self._connection.execute(
                "SELECT type, name, tbl_name FROM sqlite_schema "
                "WHERE name NOT LIKE 'sqlite_%'"
            )
        }
        if actual_objects != expected_objects:
            raise RuntimeError("SQLite schema object mismatch")
        index_columns = {
            "idx_metadata_kind": ("kind",),
            "idx_ann_lookup": ("band", "bucket", "key"),
        }
        for index_name, expected_columns in index_columns.items():
            actual_columns = tuple(
                str(row[2])
                for row in self._connection.execute(f"PRAGMA index_info({index_name})")
            )
            if actual_columns != expected_columns:
                raise RuntimeError("SQLite schema index mismatch")
        expected_foreign_keys = {
            "ann_buckets": (("metadata_index", "key", "key", "NO ACTION", "CASCADE"),),
            "eviction_metadata": (
                ("metadata_index", "key", "key", "NO ACTION", "CASCADE"),
            ),
        }
        for table, expected in expected_foreign_keys.items():
            actual = tuple(
                (
                    str(row[2]),
                    str(row[3]),
                    str(row[4]),
                    str(row[5]),
                    str(row[6]),
                )
                for row in self._connection.execute(f"PRAGMA foreign_key_list({table})")
            )
            if actual != expected:
                raise RuntimeError("SQLite schema foreign-key mismatch")

    def verify_integrity(self) -> None:
        """Raise if SQLite reports any structural database corruption."""
        with self._lock:
            self._ensure_open_locked()
            rows = self._connection.execute("PRAGMA quick_check").fetchall()
            foreign_key_rows = self._connection.execute(
                "PRAGMA foreign_key_check"
            ).fetchall()
            self._verify_ann_integrity_locked()
        results = tuple(str(row[0]) for row in rows)
        if results != ("ok",):
            raise RuntimeError("SQLite integrity check failed")
        if foreign_key_rows:
            raise RuntimeError("SQLite foreign-key integrity check failed")

    def lsh_status(self) -> dict[str, object]:
        """Return payload-free index-derivation status."""

        with self._lock:
            self._ensure_open_locked()
            self._validate_lsh_config_locked()
            indexed_row = self._connection.execute(
                "SELECT COUNT(DISTINCT key) FROM ann_buckets"
            ).fetchone()
        return {
            "schema": LSH_INDEX_SCHEMA,
            "derivation_version": LSH_INDEX_DERIVATION_VERSION,
            "projection_seed": (
                "profile-keyed"
                if self._lsh_key_custody == "profile-derived"
                else "path-derived-development"
            ),
            "bucket_identifiers": "hmac-sha256",
            "key_custody": self._lsh_key_custody,
            "protected_indexing": (
                "profile-keyed"
                if self._protected_index_hint is not None
                else "linear-fallback"
            ),
            "indexed_records": 0 if indexed_row is None else int(indexed_row[0]),
            "leakage": [
                "bucket-equality",
                "access-pattern",
                "approximate-neighborhood",
            ],
        }

    def rotate_lsh_index(self, index_key: bytes) -> dict[str, object]:
        """Rebuild every derivable bucket under a new profile key."""

        replacement = RandomProjectionLSH(index_key, self._lsh.config)
        with self._lock:
            self._ensure_open_locked()
            if replacement.key_fingerprint == self._lsh.key_fingerprint:
                return {"changed": False, **self.lsh_status()}
            previous = self._lsh
            self._begin_locked(advance_generation=False)
            try:
                self._lsh = replacement
                self._connection.execute("DELETE FROM ann_buckets")
                self._backfill_ann_locked()
                updated = self._connection.execute(
                    """
                    UPDATE ann_config SET key_fingerprint = ?
                    WHERE singleton = 1
                    """,
                    (replacement.key_fingerprint,),
                )
                if updated.rowcount != 1:
                    raise RuntimeError("LSH index configuration is missing")
                self._commit_locked()
            except Exception:
                self._lsh = previous
                self._rollback_locked()
                raise
            self._lsh_key_custody = "profile-derived"
            return {"changed": True, **self.lsh_status()}

    def managed_state_ids(
        self,
    ) -> tuple[set[str], set[str], set[str], set[str]]:
        """Return local tier IDs for adapter-level crash-consistency checks."""

        with self._lock:
            self._ensure_open_locked()
            tables = (
                "active_workspace",
                "metadata_index",
                "cold_archive",
                "eviction_metadata",
            )
            values = []
            for table in tables:
                # Table identifiers come exclusively from the immutable tuple
                # above; no caller or persisted value can influence this SQL.
                query = f"SELECT key FROM {table}"  # nosec B608
                rows = self._connection.execute(query).fetchall()
                values.append({str(row[0]) for row in rows})
        return values[0], values[1], values[2], values[3]

    def rotate_protected_payloads(
        self,
        *,
        source_key_id: str,
        limit: int,
        transform: Callable[[object], object],
        source_schema_version: int | None = None,
    ) -> dict[str, int]:
        """Re-encrypt a bounded set of protected lifecycle anchors.

        Each record is updated transactionally across its active workspace or
        matching L2/L3 copies.  Multi-key shields keep an interrupted rotation
        readable; a later call resumes by scanning for the old non-secret key
        identifier.
        """

        if not isinstance(source_key_id, str) or not source_key_id.strip():
            raise ValueError("source_key_id must be a non-empty string")
        if (
            isinstance(limit, bool)
            or not isinstance(limit, int)
            or not 1 <= limit <= 1000
        ):
            raise ValueError("rotation limit must be between 1 and 1000")
        if not callable(transform):
            raise TypeError("rotation transform must be callable")

        with self._lock:
            self._ensure_open_locked()
            active_rows = self._connection.execute(
                """
                SELECT key, payload
                FROM active_workspace
                WHERE payload_kind = 'protected'
                ORDER BY key
                """
            ).fetchall()
            indexed_rows = self._connection.execute(
                """
                SELECT key, payload
                FROM metadata_index
                WHERE kind = 'protected_anchor'
                ORDER BY key
                """
            ).fetchall()

        candidates: list[str] = []
        decoded_by_key: dict[str, object] = {}
        for key_raw, payload_raw in (*active_rows, *indexed_rows):
            key = str(key_raw)
            decoded = self._loader(bytes(payload_raw))
            if getattr(decoded, "key_id", None) != source_key_id:
                continue
            if (
                source_schema_version is not None
                and getattr(decoded, "schema_version", None) != source_schema_version
            ):
                continue
            record_id = getattr(decoded, "record_id", None)
            if record_id is not None and record_id != key:
                raise RuntimeError("protected lifecycle record ID binding is invalid")
            if key not in decoded_by_key:
                candidates.append(key)
                decoded_by_key[key] = decoded
            if len(candidates) >= limit:
                break

        migrated = 0
        for key in candidates:
            replacement = transform(decoded_by_key[key])
            if not is_serializable_protected_payload(replacement):
                raise TypeError("rotation transform returned an invalid payload")
            replacement_record_id = getattr(replacement, "record_id", None)
            if replacement_record_id is not None and replacement_record_id != key:
                raise RuntimeError("rotated lifecycle record ID binding is invalid")
            encoded = self._validate_payload(
                replacement.to_json_bytes(),
                "rotated protected",
            )
            with self._lock:
                self._ensure_open_locked()
                self._begin_locked()
                try:
                    active = self._connection.execute(
                        """
                        UPDATE active_workspace
                        SET payload = ?
                        WHERE key = ? AND payload_kind = 'protected'
                        """,
                        (encoded, key),
                    ).rowcount
                    indexed = self._connection.execute(
                        """
                        UPDATE metadata_index
                        SET payload = ?, updated_at = ?
                        WHERE key = ? AND kind = 'protected_anchor'
                        """,
                        (encoded, time.time(), key),
                    ).rowcount
                    archived = self._connection.execute(
                        """
                        UPDATE cold_archive
                        SET payload = ?, updated_at = ?
                        WHERE key = ?
                        """,
                        (encoded, time.time(), key),
                    ).rowcount
                    if not active and (indexed != 1 or archived != 1):
                        raise RuntimeError(
                            "protected lifecycle tiers disagree during rotation"
                        )
                    self._commit_locked()
                except Exception:
                    self._rollback_locked()
                    raise
            migrated += 1

        remaining = self.count_protected_payloads_for_key(
            source_key_id,
            schema_version=source_schema_version,
        )
        return {"migrated": migrated, "remaining": remaining}

    def count_protected_payloads_for_key(
        self,
        key_id: str,
        *,
        schema_version: int | None = None,
    ) -> int:
        """Count distinct lifecycle records still bound to ``key_id``."""

        if not isinstance(key_id, str) or not key_id.strip():
            raise ValueError("key_id must be a non-empty string")
        with self._lock:
            self._ensure_open_locked()
            rows = self._connection.execute(
                """
                SELECT key, payload
                FROM active_workspace
                WHERE payload_kind = 'protected'
                UNION ALL
                SELECT key, payload
                FROM metadata_index
                WHERE kind = 'protected_anchor'
                """
            ).fetchall()
        matching: set[str] = set()
        for key_raw, payload_raw in rows:
            decoded = self._loader(bytes(payload_raw))
            if getattr(decoded, "key_id", None) == key_id and (
                schema_version is None
                or getattr(decoded, "schema_version", None) == schema_version
            ):
                matching.add(str(key_raw))
        return len(matching)

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

    def delete_memory(self, key: str) -> bool:
        """Atomically delete one memory from active, index, and archive tables.

        ``secure_delete`` reduces ordinary SQLite page remnants, but this does
        not promise physical erasure from WAL files, backups, or storage media.
        """
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            self._begin_locked()
            try:
                metadata = self._connection.execute(
                    "DELETE FROM metadata_index WHERE key = ?", (key,)
                ).rowcount
                archived = self._connection.execute(
                    "DELETE FROM cold_archive WHERE key = ?", (key,)
                ).rowcount
                active = self._connection.execute(
                    "DELETE FROM active_workspace WHERE key = ?", (key,)
                ).rowcount
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise
        return any(count > 0 for count in (metadata, archived, active))

    def _prepare_eviction(
        self,
        record: EvictionRecord,
    ) -> tuple[str, str, bytes, bytes, int, str, tuple[tuple[int, bytes], ...]]:
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
        with self._lock:
            self._ensure_open_locked()
            key, kind, payload, dimension, signatures = self._prepare_index_upsert(
                IndexEntry(key=key, anchor=anchor, kind=kind)
            )
            self._begin_locked()
            try:
                self._upsert_metadata_locked(key, kind, payload, dimension)
                self._replace_ann_buckets_locked(key, signatures)
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def _upsert_index_batch(self, entries: list[IndexEntry]) -> None:
        if not isinstance(entries, list):
            raise TypeError("index batch must be a list of IndexEntry objects")
        if not entries or len(entries) > MAX_INDEX_BATCH_SIZE:
            raise ValueError(
                f"index batch must contain between 1 and {MAX_INDEX_BATCH_SIZE} entries"
            )
        if not all(isinstance(entry, IndexEntry) for entry in entries):
            raise TypeError("index batch must be a list of IndexEntry objects")
        with self._lock:
            self._ensure_open_locked()
            prepared = [self._prepare_index_upsert(entry) for entry in entries]
            keys = [entry[0] for entry in prepared]
            if len(set(keys)) != len(keys):
                raise ValueError("index batch keys must be unique")
            dimensions = {entry[3] for entry in prepared}
            if len(dimensions) != 1:
                raise ValueError("index batch dimensions must match")
            dimension = next(iter(dimensions))
            self._begin_locked()
            try:
                rows = self._connection.execute(
                    "SELECT DISTINCT dimension FROM metadata_index LIMIT 2"
                ).fetchall()
                if len(rows) > 1:
                    raise RuntimeError(
                        "metadata index contains inconsistent dimensions"
                    )
                if rows and int(rows[0][0]) != dimension:
                    raise ValueError(
                        f"dimension mismatch: expected ({int(rows[0][0])},), "
                        f"got ({dimension},)"
                    )
                for key, kind, payload, entry_dimension, signatures in prepared:
                    self._write_metadata_locked(
                        key,
                        kind,
                        payload,
                        entry_dimension,
                    )
                    self._replace_ann_buckets_locked(key, signatures)
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def _prepare_index_upsert(
        self,
        entry: IndexEntry,
    ) -> tuple[str, str, bytes, int, tuple[tuple[int, bytes], ...]]:
        MetadataIndex._validate_key(entry.key)
        self._validate_kind(entry.kind)
        payload, dimension = self._encode_index_anchor(entry.anchor, entry.kind)
        prepared_signatures = self._signatures_for_entry(entry, dimension)
        return (
            entry.key,
            entry.kind,
            payload,
            dimension,
            () if prepared_signatures is None else prepared_signatures,
        )

    def _remove_index(self, key: str) -> bool:
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            self._begin_locked()
            try:
                result = self._connection.execute(
                    "DELETE FROM metadata_index WHERE key = ?", (key,)
                )
                self._commit_locked()
                return result.rowcount > 0
            except Exception:
                self._rollback_locked()
                raise

    def _index_rows(self, query: Vector) -> list[tuple[str, str, bytes, int]]:
        with self._lock:
            self._ensure_open_locked()
            signatures = self._lsh.signatures(query)
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

    def _validate_lsh_config_locked(self) -> tuple[str, int, str, int, int]:
        row = self._connection.execute(
            """
            SELECT schema, derivation_version, key_fingerprint,
                   bands, bits_per_band
            FROM ann_config WHERE singleton = 1
            """
        ).fetchone()
        if row is None:
            raise RuntimeError("LSH index configuration is missing")
        schema = str(row[0])
        derivation_version = int(row[1])
        fingerprint = str(row[2])
        bands = int(row[3])
        bits_per_band = int(row[4])
        if (
            schema != LSH_INDEX_SCHEMA
            or derivation_version != LSH_INDEX_DERIVATION_VERSION
            or len(fingerprint) != 64
            or any(character not in "0123456789abcdef" for character in fingerprint)
            or bands != self._lsh.config.bands
            or bits_per_band != self._lsh.config.bits_per_band
        ):
            raise RuntimeError("LSH index configuration is invalid")
        return schema, derivation_version, fingerprint, bands, bits_per_band

    def _reconcile_lsh_key_locked(self) -> None:
        _schema, _version, fingerprint, _bands, _bits = (
            self._validate_lsh_config_locked()
        )
        if fingerprint == self._lsh.key_fingerprint:
            return
        self._connection.execute("DELETE FROM ann_buckets")
        self._backfill_ann_locked()
        updated = self._connection.execute(
            "UPDATE ann_config SET key_fingerprint = ? WHERE singleton = 1",
            (self._lsh.key_fingerprint,),
        )
        if updated.rowcount != 1:
            raise RuntimeError("LSH index configuration is missing")

    def _signatures_for_entry(
        self,
        entry: IndexEntry,
        dimension: int,
    ) -> tuple[tuple[int, bytes], ...] | None:
        if entry.kind == "protected_anchor":
            if self._protected_index_hint is None:
                return None
            vector = as_vector(
                self._protected_index_hint(entry.anchor),
                allow_empty=False,
                name="protected LSH index hint",
            )
        else:
            vector = as_vector(
                entry.anchor,
                allow_empty=False,
                name="LSH index anchor",
            )
        if vector.size != dimension:
            raise RuntimeError("LSH index hint dimension does not match metadata")
        return self._lsh.signatures(vector)

    def _backfill_ann_locked(self) -> None:
        rows = self._connection.execute(
            "SELECT key, kind, payload, dimension FROM metadata_index"
        ).fetchall()
        for key, kind, payload, dimension_raw in rows:
            dimension = self._validate_dimension(int(dimension_raw))
            entry = self._decode_index_entry(
                str(key),
                str(kind),
                bytes(payload),
                dimension,
            )
            signatures = self._signatures_for_entry(entry, dimension)
            self._replace_ann_buckets_locked(
                str(key),
                () if signatures is None else signatures,
            )

    def _verify_ann_integrity_locked(self) -> None:
        self._validate_lsh_config_locked()
        rows = self._connection.execute(
            "SELECT key, kind, payload, dimension FROM metadata_index"
        ).fetchall()
        for key_raw, kind_raw, payload_raw, dimension_raw in rows:
            key = str(key_raw)
            kind = str(kind_raw)
            dimension = self._validate_dimension(int(dimension_raw))
            entry = self._decode_index_entry(
                key,
                kind,
                bytes(payload_raw),
                dimension,
            )
            expected = self._signatures_for_entry(entry, dimension)
            actual = tuple(
                (int(row[0]), bytes(row[1]), bytes(row[2]))
                for row in self._connection.execute(
                    """
                    SELECT band, CAST(bucket AS BLOB), CAST(auth_tag AS BLOB)
                    FROM ann_buckets
                    WHERE key = ? ORDER BY band
                    """,
                    (key,),
                ).fetchall()
            )
            for band, token, authentication in actual:
                expected_authentication = self._lsh.bucket_authenticator(
                    key,
                    band,
                    token,
                )
                if not hmac.compare_digest(authentication, expected_authentication):
                    raise RuntimeError("LSH index bucket authentication failed")
            if expected is None:
                if actual and tuple(row[0] for row in actual) != tuple(
                    range(self._lsh.config.bands)
                ):
                    raise RuntimeError("LSH index bucket authentication failed")
                continue
            if tuple((band, token) for band, token, _tag in actual) != expected:
                raise RuntimeError("LSH index bucket authentication failed")

    def _replace_ann_buckets_locked(
        self,
        key: str,
        signatures: tuple[tuple[int, bytes], ...],
    ) -> None:
        self._connection.execute("DELETE FROM ann_buckets WHERE key = ?", (key,))
        self._connection.executemany(
            """
            INSERT INTO ann_buckets(key, band, bucket, auth_tag)
            VALUES (?, ?, ?, ?)
            """,
            (
                (
                    key,
                    band,
                    bucket,
                    self._lsh.bucket_authenticator(key, band, bucket),
                )
                for band, bucket in signatures
            ),
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
            self._begin_locked()
            try:
                self._put_archive_locked(key, validated)
                self._commit_locked()
            except Exception:
                self._rollback_locked()
                raise

    def _get_archive(self, key: str) -> bytes | None:
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            row = self._connection.execute(
                "SELECT payload FROM cold_archive WHERE key = ?",
                (key,),
            ).fetchone()
        return None if row is None else bytes(row[0])

    def _remove_archive(self, key: str) -> bool:
        MetadataIndex._validate_key(key)
        with self._lock:
            self._ensure_open_locked()
            self._begin_locked()
            try:
                result = self._connection.execute(
                    "DELETE FROM cold_archive WHERE key = ?", (key,)
                )
                self._commit_locked()
                return result.rowcount > 0
            except Exception:
                self._rollback_locked()
                raise

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
            decoded = strict_json_loads(str(row[0]))
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
            self._connection.execute("BEGIN")
            try:
                generation = self._read_generation_locked()
                rows = self._connection.execute(
                    """
                    SELECT key, topic, created_at, last_touched, state, locked,
                           score, twilight_since, payload_kind, payload, dimension,
                           twilight_cycles, crest_rank
                    FROM active_workspace ORDER BY key
                    """
                ).fetchall()
                self._connection.execute("COMMIT")
            except Exception:
                if self._connection.in_transaction:
                    self._connection.execute("ROLLBACK")
                raise
            self._workspace_generation = generation
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
        anchor: Vector = np.zeros(0, dtype=np.float64)
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
        self._write_metadata_locked(key, kind, payload, dimension)

    def _write_metadata_locked(
        self,
        key: str,
        kind: str,
        payload: bytes,
        dimension: int,
    ) -> None:
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

    def _read_generation_locked(self) -> int:
        row = self._connection.execute(
            "SELECT generation FROM workspace_generation WHERE singleton = 1"
        ).fetchone()
        if row is None:
            raise RuntimeError("workspace generation state is missing")
        generation = int(row[0])
        if generation < 0:
            raise RuntimeError("workspace generation state is invalid")
        return generation

    def _begin_locked(self, *, advance_generation: bool = True) -> None:
        self._ensure_open_locked()
        self._connection.execute("BEGIN IMMEDIATE")
        self._transaction_generation = None
        if not advance_generation:
            return
        current = self._read_generation_locked()
        if current != self._workspace_generation:
            self._connection.execute("ROLLBACK")
            raise RuntimeError("stale workspace generation; reload before writing")
        next_generation = current + 1
        updated = self._connection.execute(
            """
            UPDATE workspace_generation
            SET generation = ?
            WHERE singleton = 1 AND generation = ?
            """,
            (next_generation, current),
        )
        if updated.rowcount != 1:
            self._connection.execute("ROLLBACK")
            raise RuntimeError("stale workspace generation; reload before writing")
        self._transaction_generation = next_generation

    def _commit_locked(self) -> None:
        self._connection.execute("COMMIT")
        if self._transaction_generation is not None:
            self._workspace_generation = self._transaction_generation
        self._transaction_generation = None

    def _rollback_locked(self) -> None:
        if self._connection.in_transaction:
            self._connection.execute("ROLLBACK")
        self._transaction_generation = None

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

    def upsert_many(self, entries: list[IndexEntry]) -> None:
        """Atomically upsert one bounded batch of already constructed entries."""

        self._store._upsert_index_batch(entries)

    def remove(self, key: str) -> bool:
        return self._store._remove_index(key)

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

    def remove(self, key: str) -> bool:
        return self._store._remove_archive(key)

    def __len__(self) -> int:
        return self._store._archive_length()
