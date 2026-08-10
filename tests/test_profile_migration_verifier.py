from __future__ import annotations

from contextlib import contextmanager
import os
from pathlib import Path
from typing import Iterator

import numpy as np
import pytest

import echo_veil.migration as migration_module
from echo_veil.agent_memory import (
    PAYLOAD_SCHEMA_VERSION,
    AgentMemory,
    _LegacyEncryptedPayloadStore,
    _load_or_create_key,
    _secure_directory,
)
from echo_veil import agent_security
from echo_veil.migration import (
    ProfileMigrationVerificationError,
    verify_profile_migration,
)


def test_verifier_preserves_scoped_contracts_and_allows_reviewed_extras(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path, profile="source") as source:
        old = source.remember(
            "service region",
            "The protected service region was west.",
            effective_at=100.0,
            provenance=["evidence:old-receipt"],
        )
        current = source.remember(
            "service region",
            "The protected service region is now central.",
            effective_at=200.0,
            supersedes=[str(old["vine_id"])],
            provenance=["evidence:new-receipt"],
        )
        with AgentMemory(tmp_path, profile="target") as target:
            migrated = source.migrate_to(target, confirm=True)
            target.remember(
                "unrelated target state",
                "This record was created after the migration.",
                provenance=["task:post-migration"],
            )

    assert migrated["migrated"] == 2
    with pytest.raises(
        ProfileMigrationVerificationError,
        match="outside the verified migration",
    ):
        verify_profile_migration(
            tmp_path,
            source_profile="source",
            target_profile="target",
        )

    report = verify_profile_migration(
        tmp_path,
        source_profile="source",
        target_profile="target",
        allow_target_extras=True,
    )

    assert current["created"] is True
    assert report == {
        "verified": True,
        "source_profile": "source",
        "target_profile": "target",
        "source_security_schema": "scoped-v2",
        "target_security_schema": "scoped-v2",
        "source_records": 2,
        "target_records": 3,
        "matched_records": 2,
        "target_extra_records": 1,
        "supersession_edges_matched": 1,
        "lifecycle_contracts_preserved": True,
        "legacy_records_normalized_to_short_term": False,
        "target_all_records_shielded": True,
        "target_unindexed_records": 0,
        "plaintext_export_created": False,
    }


def test_verifier_proves_legacy_normalization_without_plaintext_export(
    tmp_path: Path,
) -> None:
    source_dir = tmp_path / "legacy"
    _secure_directory(source_dir)
    key_path = source_dir / "agent.key"
    key = _load_or_create_key(key_path)
    vector = np.array([1.0, 0.0, 0.0], dtype=np.float64)
    store = _LegacyEncryptedPayloadStore(source_dir / "payloads.db", key)
    try:
        old_payload = "The migration source was the west profile."
        store.put(
            "legacy-old",
            "migration source",
            old_payload,
            store.digest("migration source", old_payload),
            vectors=[vector],
            effective_at=100.0,
            supersedes=(),
        )
        new_payload = "The migration source is the central profile."
        store.put(
            "legacy-new",
            "migration source",
            new_payload,
            store.digest("migration source", new_payload),
            vectors=[vector],
            effective_at=200.0,
            supersedes=("legacy-old",),
        )
    finally:
        store.close()

    with AgentMemory(tmp_path, profile="target") as target:
        old = target.remember(
            "migration source",
            old_payload,
            effective_at=100.0,
            provenance=["migration:profile-transfer"],
        )
        target.remember(
            "migration source",
            new_payload,
            effective_at=200.0,
            supersedes=[str(old["vine_id"])],
            provenance=["migration:profile-transfer"],
        )

    report = verify_profile_migration(
        tmp_path,
        source_profile="legacy",
        target_profile="target",
    )

    assert report["verified"] is True
    assert report["matched_records"] == 2
    assert report["supersession_edges_matched"] == 1
    assert report["lifecycle_contracts_preserved"] is False
    assert report["legacy_records_normalized_to_short_term"] is True
    assert report["plaintext_export_created"] is False


def test_verifier_rejects_content_mismatch(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, profile="source") as source:
        source.remember("policy", "Use the reviewed source policy.")
    with AgentMemory(tmp_path, profile="target") as target:
        target.remember("policy", "Use an unrelated target policy.")

    with pytest.raises(
        ProfileMigrationVerificationError,
        match="missing one or more source records",
    ):
        verify_profile_migration(
            tmp_path,
            source_profile="source",
            target_profile="target",
            allow_target_extras=True,
        )


def test_windows_read_only_store_holds_ancestry_pin_through_close(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile_dir = tmp_path / "source"
    profile_dir.mkdir()
    events: list[str] = []
    state = {"pinned": False}

    @contextmanager
    def pinned_chain(path: Path) -> Iterator[tuple[()]]:
        assert path == profile_dir.absolute()
        events.append("chain-enter")
        state["pinned"] = True
        try:
            yield ()
        finally:
            assert state["pinned"] is True
            events.append("chain-exit")
            state["pinned"] = False

    def verify_leaf(path: Path) -> None:
        assert path == profile_dir.absolute()
        assert state["pinned"] is True
        events.append("leaf-verify")

    def payload_version(path: Path) -> int:
        assert path == profile_dir.absolute() / "payloads.db"
        assert state["pinned"] is True
        events.append("payload-version")
        return PAYLOAD_SCHEMA_VERSION

    class _Keyring:
        def __init__(
            self,
            path: Path,
            scope: str,
            *,
            create: bool,
        ) -> None:
            assert path == profile_dir.absolute()
            assert scope == "local-user"
            assert create is False
            assert state["pinned"] is True
            events.append("keyring-open")

    class _Store:
        def __init__(
            self,
            path: Path,
            *,
            keyring: _Keyring,
            read_only: bool,
        ) -> None:
            assert path == profile_dir.absolute() / "payloads.db"
            assert isinstance(keyring, _Keyring)
            assert read_only is True
            assert state["pinned"] is True
            events.append("store-open")

        def close(self) -> None:
            assert state["pinned"] is True
            events.append("store-close")

    class _WindowsOS:
        name = "nt"

    monkeypatch.setattr(migration_module, "os", _WindowsOS())
    monkeypatch.setattr(migration_module, "_reject_symlink_components", lambda _: None)
    monkeypatch.setattr(
        migration_module,
        "_windows_pinned_directory_chain",
        pinned_chain,
    )
    monkeypatch.setattr(
        migration_module,
        "_windows_verify_private_directory",
        verify_leaf,
    )
    monkeypatch.setattr(
        migration_module,
        "_payload_database_version",
        payload_version,
    )
    monkeypatch.setattr(migration_module, "ProfileKeyring", _Keyring)
    monkeypatch.setattr(migration_module, "_EncryptedPayloadStore", _Store)

    with migration_module._read_only_store(
        tmp_path,
        profile="source",
        scope="local-user",
    ):
        assert state["pinned"] is True
        events.append("yield")

    assert events == [
        "chain-enter",
        "leaf-verify",
        "payload-version",
        "keyring-open",
        "store-open",
        "yield",
        "store-close",
        "chain-exit",
    ]


@pytest.mark.skipif(os.name != "nt", reason="Windows native ancestry contract")
def test_windows_read_only_store_rejects_private_leaf_below_reparse_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    real_parent = agent_security._windows_ensure_private_directory(
        tmp_path / "real-parent"
    )
    agent_security._windows_ensure_private_directory(real_parent / "source")
    redirected_parent = tmp_path / "redirected-parent"
    try:
        redirected_parent.symlink_to(real_parent, target_is_directory=True)
    except OSError:
        pytest.skip(
            "directory symlink creation is unavailable for this Windows account"
        )
    # Exercise the native pinned-chain proof even if the preliminary generic
    # component check could also identify this reparse point.
    monkeypatch.setattr(migration_module, "_reject_symlink_components", lambda _: None)

    with pytest.raises(
        ProfileMigrationVerificationError,
        match="Windows DACL or ancestry is unsafe",
    ):
        with migration_module._read_only_store(
            redirected_parent,
            profile="source",
            scope="local-user",
        ):
            pytest.fail("unsafe Windows ancestry must fail before opening the store")
