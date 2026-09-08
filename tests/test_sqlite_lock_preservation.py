"""Security inspection must not cancel SQLite's process-owned file locks."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys

import pytest

from echo_veil import agent_memory, agent_security
from echo_veil.persistence import SQLiteStore


pytestmark = pytest.mark.skipif(os.name == "nt", reason="POSIX close/lock contract")

CONTENDER = """
import json, sqlite3, sys
connection = sqlite3.connect(sys.argv[1], timeout=0.1, isolation_level=None)
try:
    connection.execute('BEGIN IMMEDIATE')
    print(json.dumps({'writer_acquired': True}))
    connection.rollback()
except sqlite3.OperationalError as exc:
    print(json.dumps({'writer_acquired': False, 'error': str(exc)}))
finally:
    connection.close()
"""


def _writer_blocked(path: Path) -> bool:
    result = subprocess.run(
        [sys.executable, "-I", "-c", CONTENDER, str(path)],
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    observed = json.loads(result.stdout)
    if not observed["writer_acquired"]:
        assert observed["error"] == "database is locked"
    return not observed["writer_acquired"]


@pytest.mark.parametrize("journal", ["DELETE", "WAL"])
@pytest.mark.parametrize(
    "validator",
    [
        "agent_verify",
        "store_verify",
        "agent_require",
        "agent_prepare",
        "store_prepare",
        "profile_audit",
    ],
)
def test_security_inspection_preserves_live_writer_lock(
    tmp_path: Path, journal: str, validator: str
) -> None:
    root = tmp_path.resolve() / "private"
    root.mkdir(mode=0o700)
    path = root / "canary.db"
    path.touch(mode=0o600)
    connection = sqlite3.connect(path, isolation_level=None)
    try:
        assert (
            connection.execute(f"PRAGMA journal_mode={journal}").fetchone()[0].upper()
            == journal
        )
        connection.execute("CREATE TABLE canary (value INTEGER)")
        connection.execute("BEGIN IMMEDIATE")
        assert _writer_blocked(path)
        if validator == "agent_verify":
            agent_memory._verify_private_sqlite_files(path, "canary")
        elif validator == "store_verify":
            SQLiteStore._verify_database_files(str(path), None)
        elif validator == "agent_require":
            agent_memory._require_secure_regular_file(path, "canary")
        elif validator == "agent_prepare":
            agent_memory._secure_regular_file(path)
        elif validator == "store_prepare":
            SQLiteStore._secure_database_file(str(path))
        else:
            assert agent_memory._profile_access_is_owner_only(root)
        assert connection.in_transaction
        assert _writer_blocked(path), f"{validator} canceled the {journal} writer lock"
    finally:
        connection.rollback()
        connection.close()


@pytest.mark.parametrize("unsafe", ["symlink", "hardlink", "permissions", "directory"])
def test_sqlite_metadata_inspection_rejects_unsafe_leaf(
    tmp_path: Path, unsafe: str
) -> None:
    root = tmp_path.resolve() / "private"
    root.mkdir(mode=0o700)
    path = root / "canary.db"
    path.touch(mode=0o600)
    if unsafe == "symlink":
        target = root / "target"
        path.rename(target)
        path.symlink_to(target)
    elif unsafe == "hardlink":
        os.link(path, root / "alias")
    elif unsafe == "permissions":
        path.chmod(0o644)
    else:
        path.unlink()
        path.mkdir()
    with pytest.raises((OSError, RuntimeError, ValueError)):
        agent_memory._verify_private_sqlite_files(path, "canary")
    with pytest.raises((OSError, RuntimeError, ValueError)):
        SQLiteStore._verify_database_files(str(path), None)


def test_sqlite_metadata_inspection_preserves_expected_identity(tmp_path: Path) -> None:
    root = tmp_path.resolve() / "private"
    root.mkdir(mode=0o700)
    path = root / "canary.db"
    path.touch(mode=0o600)
    expected = agent_security._posix_identity(path.stat())
    path.rename(root / "original.db")
    path.touch(mode=0o600)
    with pytest.raises(ValueError, match="identity"):
        SQLiteStore._verify_database_files(str(path), expected)


@pytest.mark.parametrize("change", ["replace", "permissions", "parent"])
def test_metadata_inspection_detects_namespace_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str
) -> None:
    root = tmp_path.resolve() / "private"
    root.mkdir(mode=0o700)
    path = root / "canary.db"
    path.touch(mode=0o600)
    original_stat = os.stat
    changed = False

    def changing_stat(name, *args, **kwargs):
        nonlocal changed
        information = original_stat(name, *args, **kwargs)
        if name == path.name and kwargs.get("dir_fd") is not None and not changed:
            changed = True
            if change == "replace":
                path.rename(root / "original.db")
                path.touch(mode=0o600)
            elif change == "permissions":
                path.chmod(0o400)
            else:
                root.rename(root.with_name("moved"))
                root.mkdir(mode=0o700)
        return information

    monkeypatch.setattr(agent_security.os, "stat", changing_stat)
    with pytest.raises(OSError, match="identity"):
        agent_security._posix_stat_private_file(path, label="canary")
    assert changed


def test_existing_database_and_sidecars_are_never_opened_for_inspection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = tmp_path.resolve() / "private"
    root.mkdir(mode=0o700)
    path = root / "canary.db"
    names = {path.name, f"{path.name}-wal", f"{path.name}-shm", f"{path.name}-journal"}
    for name in names:
        (root / name).touch(mode=0o600)
    original_open = os.open

    def checked_open(name, flags, *args, **kwargs):
        if name in names:
            assert flags & os.O_CREAT and flags & os.O_EXCL
        return original_open(name, flags, *args, **kwargs)

    monkeypatch.setattr(agent_security.os, "open", checked_open)
    agent_memory._secure_regular_file(path)
    agent_memory._verify_private_sqlite_files(path, "canary")
    SQLiteStore._secure_database_file(str(path))
    SQLiteStore._verify_database_files(str(path), None)
    assert agent_memory._profile_access_is_owner_only(root)
