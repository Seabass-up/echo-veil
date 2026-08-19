from __future__ import annotations

import os
import sqlite3
import stat
import time
from pathlib import Path

import numpy as np
import pytest

import echo_veil.agent_security as agent_security
import echo_veil.persistence as persistence_module
from echo_veil import (
    AesGcmCryptoShield,
    Oracle,
    SQLiteStore,
    Vine,
    VineState,
    WorkspaceConfig,
)
from echo_veil.archive import EvictionRecord
from echo_veil.capability import CapabilityStatus
from echo_veil.vectors import cosine_similarity


def _database_path(tmp_path: Path, filename: str) -> Path:
    state_dir = tmp_path / "echo-veil-private-state"
    if os.name == "nt":
        agent_security._windows_ensure_private_directory(
            state_dir,
            harden_existing=False,
        )
    else:
        state_dir.mkdir(mode=0o700, exist_ok=True)
    return state_dir / filename


def _windows_directory_security_snapshot(path: Path) -> tuple[bytes, bytes, int]:
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetSecurityInfo.restype = wintypes.DWORD
    advapi32.GetSecurityDescriptorControl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    handle = agent_security._windows_open_directory_handle(path)
    security_descriptor = ctypes.c_void_p()
    try:
        result = advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            1,  # SE_FILE_OBJECT
            0x00000001 | 0x00000004,  # OWNER | DACL
            None,
            None,
            None,
            None,
            ctypes.byref(security_descriptor),
        )
        if result != 0:
            raise ctypes.WinError(result)
        control = wintypes.WORD()
        revision = wintypes.DWORD()
        if not advapi32.GetSecurityDescriptorControl(
            security_descriptor,
            ctypes.byref(control),
            ctypes.byref(revision),
        ):
            raise ctypes.WinError(ctypes.get_last_error())
        owner, dacl = agent_security._windows_security_descriptor_fingerprint(
            security_descriptor,
            require_protected=False,
        )
        return owner, dacl, int(control.value)
    finally:
        if security_descriptor.value:
            kernel32.LocalFree(security_descriptor)
        kernel32.CloseHandle(wintypes.HANDLE(handle))


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
    path = _database_path(tmp_path, "echo-veil.db")
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
    path = _database_path(tmp_path, "shared.db")
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
    store = _FailingMetadataStore(_database_path(tmp_path, "rollback.db"))
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
    store = _FailingMetadataStore(_database_path(tmp_path, "oracle-retry.db"))
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
    path = _database_path(tmp_path, "protected.db")
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
    with SQLiteStore(_database_path(tmp_path, "ready.db")) as store:
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


def test_windows_store_requests_validation_without_parent_hardening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[Path, bool]] = []

    class _WindowsOS:
        name = "nt"
        fspath = staticmethod(os.fspath)

    def ensure_private(path: Path, *, harden_existing: bool) -> Path:
        calls.append((path, harden_existing))
        return path

    monkeypatch.setattr(persistence_module, "os", _WindowsOS())
    monkeypatch.setattr(
        persistence_module,
        "_windows_ensure_private_directory",
        ensure_private,
    )

    database_path, durable = SQLiteStore._prepare_path(tmp_path / "store.db")

    assert database_path == str((tmp_path / "store.db").absolute())
    assert durable is True
    assert calls == [(tmp_path.absolute(), False)]


def test_windows_database_create_rechecks_pinned_parent_without_hardening(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    database_path = tmp_path / "store.db"
    events: list[str] = []
    state = {"pinned": False}

    class _WindowsOS:
        name = "nt"

        @staticmethod
        def close(descriptor: int) -> None:
            assert descriptor == 41
            events.append("descriptor-close")

    class _PinnedChain:
        def __enter__(self) -> tuple[()]:
            state["pinned"] = True
            events.append("chain-enter")
            return ()

        def __exit__(self, *_args: object) -> None:
            events.append("chain-exit")
            state["pinned"] = False

    def ensure_private(path: Path, *, harden_existing: bool) -> Path:
        assert path == tmp_path
        assert harden_existing is False
        events.append("parent-validate-only")
        return path

    def verify_parent(path: Path) -> None:
        assert path == tmp_path
        assert state["pinned"] is True
        events.append("parent-reverify")

    def create_private(path: Path) -> tuple[int, tuple[object, ...]]:
        assert path == database_path
        assert state["pinned"] is True
        events.append("file-create")
        return 41, (object(),)

    monkeypatch.setattr(persistence_module, "os", _WindowsOS())
    monkeypatch.setattr(
        persistence_module,
        "_windows_ensure_private_directory",
        ensure_private,
    )
    monkeypatch.setattr(
        persistence_module,
        "_windows_pinned_directory_chain",
        lambda path: _PinnedChain() if path == tmp_path else pytest.fail(),
    )
    monkeypatch.setattr(
        persistence_module,
        "_windows_verify_private_directory",
        verify_parent,
    )
    monkeypatch.setattr(
        persistence_module,
        "_windows_create_private_staging",
        create_private,
    )
    monkeypatch.setattr(
        persistence_module,
        "_windows_verify_descriptor",
        lambda *_args, **_kwargs: events.append("file-verify"),
    )
    monkeypatch.setattr(
        persistence_module,
        "_windows_verify_private_sqlite_sidecars",
        lambda path: (
            events.append("sidecar-verify") if path == database_path else pytest.fail()
        ),
    )

    SQLiteStore._secure_database_file(str(database_path))

    assert events == [
        "parent-validate-only",
        "chain-enter",
        "parent-reverify",
        "file-create",
        "file-verify",
        "descriptor-close",
        "chain-exit",
        "sidecar-verify",
    ]


def test_windows_private_directory_validation_mode_never_calls_hardener(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []

    class _WindowsOS:
        name = "nt"
        path = os.path
        fspath = staticmethod(os.fspath)

    def reject_broad_directory(_path: Path) -> None:
        events.append("verify")
        raise OSError("broad inherited DACL")

    monkeypatch.setattr(agent_security, "os", _WindowsOS())
    monkeypatch.setattr(
        agent_security,
        "_windows_verify_private_directory",
        reject_broad_directory,
    )
    monkeypatch.setattr(
        agent_security,
        "_windows_harden_private_directory",
        lambda _path: pytest.fail("caller-owned parent must not be hardened"),
    )

    with pytest.raises(OSError, match="broad inherited DACL"):
        agent_security._windows_ensure_private_directory(
            tmp_path,
            harden_existing=False,
        )

    assert events == ["verify"]


@pytest.mark.skipif(os.name != "nt", reason="Windows native parent-DACL contract")
def test_windows_store_never_rewrites_existing_parent_dacl(tmp_path: Path) -> None:
    shared_parent = tmp_path / "shared-parent"
    shared_parent.mkdir()
    shared_before = _windows_directory_security_snapshot(shared_parent)

    with pytest.raises(OSError, match="Windows|private|DACL"):
        SQLiteStore(shared_parent / "rejected.db")

    assert not (shared_parent / "rejected.db").exists()
    assert _windows_directory_security_snapshot(shared_parent) == shared_before

    private_parent = agent_security._windows_ensure_private_directory(
        tmp_path / "dedicated-private-parent"
    )
    private_before = _windows_directory_security_snapshot(private_parent)
    with SQLiteStore(private_parent / "accepted.db"):
        pass
    assert _windows_directory_security_snapshot(private_parent) == private_before


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission bits only")
def test_database_file_permissions_are_owner_only(tmp_path: Path) -> None:
    path = _database_path(tmp_path, "private.db")
    with SQLiteStore(path):
        mode = stat.S_IMODE(os.stat(path).st_mode)
        assert mode == 0o600


def test_sqlite_secure_delete_is_enabled(tmp_path: Path) -> None:
    with SQLiteStore(_database_path(tmp_path, "secure-delete.db")) as store:
        row = store._connection.execute("PRAGMA secure_delete").fetchone()
        assert row == (1,)


def test_unknown_schema_version_fails_closed(tmp_path: Path) -> None:
    path = _database_path(tmp_path, "future.db")
    SQLiteStore._secure_database_file(str(path))
    connection = sqlite3.connect(path)
    connection.execute("PRAGMA user_version = 99")
    connection.close()

    with pytest.raises(RuntimeError, match="unsupported.*schema version"):
        SQLiteStore(path)


def test_malformed_existing_schema_fails_closed(tmp_path: Path) -> None:
    path = _database_path(tmp_path, "malformed.db")
    SQLiteStore._secure_database_file(str(path))
    connection = sqlite3.connect(path)
    connection.execute("CREATE TABLE metadata_index (wrong_column TEXT)")
    connection.close()

    with pytest.raises(RuntimeError, match="schema mismatch"):
        SQLiteStore(path)


def test_sqlite_store_rejects_symbolic_link_path_components(tmp_path: Path) -> None:
    real = tmp_path / "real"
    real.mkdir()
    linked = tmp_path / "linked"
    try:
        linked.symlink_to(real, target_is_directory=True)
    except OSError:
        pytest.skip("symbolic links are unavailable")

    with pytest.raises(ValueError, match="symbolic links"):
        SQLiteStore(linked / "echo-veil.db")


def test_sqlite_store_rejects_unexpected_schema_objects(tmp_path: Path) -> None:
    path = _database_path(tmp_path, "injected.db")
    with SQLiteStore(path):
        pass
    connection = sqlite3.connect(path)
    connection.execute(
        "CREATE TRIGGER injected_trigger BEFORE DELETE ON cold_archive "
        "BEGIN SELECT RAISE(ABORT, 'blocked'); END"
    )
    connection.close()

    with pytest.raises(RuntimeError, match="schema object mismatch"):
        SQLiteStore(path)


def test_closed_store_rejects_access(tmp_path: Path) -> None:
    store = SQLiteStore(_database_path(tmp_path, "closed.db"))
    store.close()
    store.close()

    with pytest.raises(RuntimeError, match="closed"):
        len(store.index)


def test_oracle_rejects_incomplete_storage_backend() -> None:
    with pytest.raises(TypeError, match="deletion APIs"):
        Oracle(storage=object())  # type: ignore[arg-type]


def test_forget_deletes_active_protected_memory_and_clears_live_material(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path, "forget-active.db")
    key = AesGcmCryptoShield.generate_key()
    with SQLiteStore(path) as store:
        oracle = Oracle(
            shield=AesGcmCryptoShield(key),
            environment="staging",
            storage=store,
        )
        vine = oracle.sprout("forget me", np.array([1.0, 0.0]))
        assert vine.protected_anchor is not None

        assert oracle.forget(vine.vine_id) is True
        assert oracle.forget(vine.vine_id) is False
        assert oracle.workspace.get(vine.vine_id) is None
        assert vine.anchor.size == 0
        assert vine.protected_anchor is None

    with SQLiteStore(path) as restored_store:
        restored = Oracle(
            shield=AesGcmCryptoShield(key),
            environment="staging",
            storage=restored_store,
        )
        assert restored.workspace.get(vine.vine_id) is None


def test_forget_atomically_deletes_archived_memory_across_restart(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path, "forget-archived.db")
    with SQLiteStore(path) as store:
        oracle = Oracle(
            WorkspaceConfig(capacity=2, pressure_evict_at=0.0),
            storage=store,
        )
        vine = oracle.sprout("archived", np.array([0.0, 1.0]))
        now = time.time()
        oracle.observe(np.array([1.0, 0.0]), now=now)
        oracle.observe(
            np.array([1.0, 0.0]),
            now=now + 31 * 60,
            cycles_since_twilight={vine.vine_id: 5},
        )
        assert store.archive.get(vine.vine_id) is not None
        assert oracle.archived_metadata(vine.vine_id) is not None

        assert oracle.forget(vine.vine_id) is True
        assert oracle.search_index(np.array([0.0, 1.0]), top_k=5) == []
        assert store.archive.get(vine.vine_id) is None
        assert oracle.archived_metadata(vine.vine_id) is None

    with SQLiteStore(path) as restored_store:
        restored = Oracle(storage=restored_store)
        assert restored.search_index(np.array([0.0, 1.0]), top_k=5) == []
        assert restored_store.archive.get(vine.vine_id) is None


def test_forget_rolls_back_durable_deletion_before_releasing_live_vine(
    tmp_path: Path,
) -> None:
    with SQLiteStore(_database_path(tmp_path, "forget-rollback.db")) as store:
        oracle = Oracle(storage=store)
        vine = oracle.sprout("retry deletion", np.array([1.0, 0.0]))
        store._connection.execute(
            "CREATE TRIGGER fail_active_delete BEFORE DELETE ON active_workspace "
            "BEGIN SELECT RAISE(ABORT, 'simulated deletion failure'); END"
        )

        with pytest.raises(sqlite3.IntegrityError, match="deletion failure"):
            oracle.forget(vine.vine_id)

        assert oracle.workspace.get(vine.vine_id) is vine
        persisted = store.load_workspace()[0]
        assert [item.vine_id for item in persisted] == [vine.vine_id]
        assert vine.anchor.size == 2


def test_active_workspace_is_checkpointed_and_restored(tmp_path: Path) -> None:
    path = _database_path(tmp_path, "active.db")
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
    with SQLiteStore(_database_path(tmp_path, "ann.db")) as store:
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
    path = _database_path(tmp_path, "v1.db")
    SQLiteStore._secure_database_file(str(path))
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
        assert version_row is not None and version_row[0] == 3


def test_workspace_generation_rejects_a_stale_cross_process_snapshot(
    tmp_path: Path,
) -> None:
    path = _database_path(tmp_path, "generation-cas.db")
    first = SQLiteStore(path)
    second = SQLiteStore(path)
    try:
        assert first.load_workspace()[0] == []
        assert second.load_workspace()[0] == []
        first_vine = Vine(topic="first", anchor=np.array([1.0, 0.0]))
        second_vine = Vine(topic="second", anchor=np.array([0.0, 1.0]))

        first.save_workspace([first_vine], {}, ())
        with pytest.raises(RuntimeError, match="stale workspace generation"):
            second.save_workspace([second_vine], {}, ())

        restored, _, _ = second.load_workspace()
        assert [vine.vine_id for vine in restored] == [first_vine.vine_id]
    finally:
        first.close()
        second.close()
