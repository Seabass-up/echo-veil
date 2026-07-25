from __future__ import annotations

from pathlib import Path

import numpy as np
import pytest

from echo_veil.agent_memory import AgentMemory, _LegacyEncryptedPayloadStore
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
    source_dir.mkdir(mode=0o700)
    key = b"k" * 32
    key_path = source_dir / "agent.key"
    key_path.write_bytes(key)
    key_path.chmod(0o600)
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
