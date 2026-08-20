from __future__ import annotations

import json
from pathlib import Path
import sqlite3

import numpy as np
import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from echo_veil.agent_cli import dispatch
from echo_veil.agent_memory import AgentMemory, AlwaysAvailableMemory
from echo_veil.agent_security import ProfileKeyring, scoped_aad
from echo_veil.preflight_receipt import PREFLIGHT_RECEIPT_SCHEMA
from echo_veil.record_envelope import (
    KEY_PURPOSE_PAYLOAD,
    KEY_PURPOSE_VECTOR,
    RECORD_ENVELOPE_KEY_PURPOSES,
    RECORD_ENVELOPE_V2,
    RECORD_ENVELOPE_V3,
    RECORD_ENVELOPE_V3_FEATURE,
    derive_record_envelope_key,
)


class _SemanticEmbedder:
    identity = (
        "ollama:qwen3-embedding:latest@sha256:"
        + "a" * 64
        + ":dimension:1024:instruction:"
        + "b" * 64
    )
    name = "ollama"
    model = "qwen3-embedding:latest"
    dimension = 1024
    semantic = True
    default_min_score = 0.44

    def embed_document(self, _text: str) -> np.ndarray:
        vector = np.zeros(self.dimension, dtype=np.float64)
        vector[0] = 1.0
        return vector

    def embed_query(self, _text: str) -> np.ndarray:
        return self.embed_document(_text)

    def embed_retrieval_queries(self, text: str) -> tuple[np.ndarray, np.ndarray]:
        vector = self.embed_query(text)
        return vector, vector.copy()


def _versions(profile_dir: Path, table: str) -> dict[int, int]:
    connection = sqlite3.connect(profile_dir / "payloads.db")
    try:
        return {
            int(version): int(count)
            for version, count in connection.execute(
                f"SELECT format_version, COUNT(*) FROM {table} "  # nosec B608
                "GROUP BY format_version"
            ).fetchall()
        }
    finally:
        connection.close()


def _receipt_inputs() -> dict[str, str]:
    return {
        "session_id": "session-v3-compat",
        "turn_id": "turn-v3-compat",
        "model_digest": "sha256:" + "1" * 64,
        "tool_manifest_digest": "sha256:" + "2" * 64,
        "artifact_authority_id": "sha256:" + "3" * 64,
    }


def test_v3_hkdf_domains_bind_scope_epoch_purpose_version_and_algorithm() -> None:
    root = b"r" * 32
    derived = {
        purpose: derive_record_envelope_key(
            root,
            profile_scope="local-user",
            scope_id="scope-" + "a" * 32,
            key_epoch=1,
            purpose=purpose,
        )
        for purpose in RECORD_ENVELOPE_KEY_PURPOSES
    }

    assert len(set(derived.values())) == len(RECORD_ENVELOPE_KEY_PURPOSES)
    assert all(len(value) == 32 for value in derived.values())
    assert derived[KEY_PURPOSE_PAYLOAD] != derived[KEY_PURPOSE_VECTOR]
    assert derived[KEY_PURPOSE_PAYLOAD] != derive_record_envelope_key(
        root,
        profile_scope="other-user",
        scope_id="scope-" + "a" * 32,
        key_epoch=1,
        purpose=KEY_PURPOSE_PAYLOAD,
    )
    assert derived[KEY_PURPOSE_PAYLOAD] != derive_record_envelope_key(
        root,
        profile_scope="local-user",
        scope_id="scope-" + "b" * 32,
        key_epoch=1,
        purpose=KEY_PURPOSE_PAYLOAD,
    )
    assert derived[KEY_PURPOSE_PAYLOAD] != derive_record_envelope_key(
        root,
        profile_scope="local-user",
        scope_id="scope-" + "a" * 32,
        key_epoch=2,
        purpose=KEY_PURPOSE_PAYLOAD,
    )


def test_v3_activation_is_explicit_and_persists_a_downgrade_barrier(
    tmp_path: Path,
) -> None:
    with AgentMemory(
        tmp_path, profile="explicit-v3", embed=_SemanticEmbedder()
    ) as memory:
        memory.remember("policy", "Version two remains readable.", provenance=["test"])
        profile_dir = memory.profile_dir
        keyring_before = json.loads((profile_dir / "keyring.json").read_text())

        assert _versions(profile_dir, "payloads") == {RECORD_ENVELOPE_V2: 1}
        assert RECORD_ENVELOPE_V3_FEATURE not in keyring_before.get("features", [])
        assert memory.doctor()["record_envelope"]["migration_state"] == "inactive"

        result = memory.migrate_record_envelope_v3(confirm=True, batch_size=1)

        keyring_after = json.loads((profile_dir / "keyring.json").read_text())
        connection = sqlite3.connect(profile_dir / "payloads.db")
        try:
            objects = {
                str(row[0])
                for row in connection.execute(
                    "SELECT name FROM sqlite_schema WHERE type = 'table'"
                ).fetchall()
            }
        finally:
            connection.close()
        assert result["preflight_protocol"] == "preflight_v2"
        assert result["lsh_index_rekeyed"] is True
        assert RECORD_ENVELOPE_V3_FEATURE in keyring_after["features"]
        assert keyring_after["keys"][keyring_after["active_key_id"]]["epoch"] == 1
        assert "record_envelope_state" in objects
        assert memory.doctor()["record_envelope"]["write_version"] == 3


@pytest.mark.parametrize("batch_size", [False, 0, 1001])
def test_v3_migration_requires_confirmation_and_a_bounded_batch(
    tmp_path: Path,
    batch_size: object,
) -> None:
    with AgentMemory(tmp_path, embed=_SemanticEmbedder()) as memory:
        with pytest.raises(ValueError, match="confirm=true"):
            memory.migrate_record_envelope_v3()
        with pytest.raises(ValueError, match="batch_size"):
            memory.migrate_record_envelope_v3(  # type: ignore[arg-type]
                confirm=True,
                batch_size=batch_size,
            )


def test_v3_activation_resumes_after_interruption_before_key_schedule_commit(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = "interrupted-v3"
    with AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder()) as memory:
        memory.remember("migration", "The v2 record must survive activation.")
        assert memory._keyring is not None

        def fail_activation() -> None:
            raise RuntimeError("synthetic interruption")

        monkeypatch.setattr(
            memory._keyring,
            "enable_record_envelope_v3",
            fail_activation,
        )
        with pytest.raises(RuntimeError, match="synthetic interruption"):
            memory.migrate_record_envelope_v3(confirm=True, batch_size=1)
        assert memory._payloads.record_envelope_status()["migration_state"] == (
            "prepared"
        )

    with AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder()) as resumed:
        status = resumed.doctor()["record_envelope"]
        assert status["migration_state"] == "migrating"
        assert resumed.list_memories()[0]["payload"] == (
            "The v2 record must survive activation."
        )
        final = resumed.migrate_record_envelope_v3(confirm=True, batch_size=100)
        assert final["state"] == "verified"


def test_mixed_v2_v3_profile_resumes_after_restart_and_keeps_preflight_v2(
    tmp_path: Path,
) -> None:
    profile = "mixed-v3"
    payloads = [f"Protected migration record {index}." for index in range(4)]
    with AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder()) as memory:
        for payload in payloads:
            memory.remember("migration", payload, provenance=["test"])
        first = memory.migrate_record_envelope_v3(confirm=True, batch_size=2)
        assert first["state"] == "migrating"
        assert first["remaining_v2_records"] > 0

    with AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder()) as memory:
        listed = memory.list_memories(limit=10)
        assert {record["payload"] for record in listed} == set(payloads)
        memory.remember(
            "migration",
            "A newly written record uses envelope v3.",
            provenance=["test"],
        )
        response = dispatch(
            memory,
            "preflight_v2",
            {
                "query": "What migration records are protected?",
                "expected_profile": profile,
                "expected_scope": "local-user",
                "query_source": "current_user_prompt",
                **_receipt_inputs(),
            },
            caller="codex",
        )
        for _attempt in range(10):
            final = memory.migrate_record_envelope_v3(confirm=True, batch_size=2)
            if final["state"] == "verified":
                break
        else:  # pragma: no cover - bounded records must finish well before this
            raise AssertionError("record-envelope migration did not converge")

        assert response["schema"] == PREFLIGHT_RECEIPT_SCHEMA
        assert "record_envelope" not in response
        assert final["remaining_v2_records"] == 0
        assert final["remaining_v2_lifecycle_records"] == 0
        assert memory.doctor()["record_envelope"]["migration_state"] == "verified"

    profile_dir = tmp_path / profile
    assert _versions(profile_dir, "payloads") == {RECORD_ENVELOPE_V3: 5}
    assert set(_versions(profile_dir, "memory_terms")) == {RECORD_ENVELOPE_V3}
    with AlwaysAvailableMemory(tmp_path, profile=profile) as offline:
        assert len(offline.list_memories(limit=10)) == 5
        assert offline.doctor()["record_envelope"]["migration_state"] == "verified"


def test_v3_migrates_authenticated_tombstones_and_rejects_wrong_scope(
    tmp_path: Path,
) -> None:
    with AgentMemory(
        tmp_path, profile="v3-tombstone", embed=_SemanticEmbedder()
    ) as memory:
        created = memory.remember(
            "temporary",
            "This protected record will be deleted.",
            provenance=["test"],
        )
        memory.forget(str(created["vine_id"]))
        for _attempt in range(10):
            result = memory.migrate_record_envelope_v3(confirm=True, batch_size=1)
            if result["state"] == "verified":
                break
        assert result["remaining_v2_tombstones"] == 0
        assert memory.doctor()["authenticated_deletion_records"] == 1

    assert _versions(tmp_path / "v3-tombstone", "deletion_tombstones") == {
        RECORD_ENVELOPE_V3: 1
    }
    with pytest.raises(PermissionError, match="scope"):
        AgentMemory(
            tmp_path,
            profile="v3-tombstone",
            scope="another-user",
            embed=_SemanticEmbedder(),
        )


def test_v3_payload_rejects_a_key_from_the_vector_domain(tmp_path: Path) -> None:
    with AgentMemory(tmp_path, embed=_SemanticEmbedder()) as memory:
        created = memory.remember(
            "domain separation",
            "Payload and vector keys are independently derived.",
        )
        result = memory.migrate_record_envelope_v3(confirm=True, batch_size=100)
        assert result["state"] == "verified"
        assert memory._keyring is not None
        connection = sqlite3.connect(memory.profile_dir / "payloads.db")
        try:
            row = connection.execute(
                """
                SELECT CAST(nonce AS BLOB), CAST(ciphertext AS BLOB),
                       key_id, scope_id, format_version
                FROM payloads WHERE vine_id = ?
                """,
                (str(created["vine_id"]),),
            ).fetchone()
        finally:
            connection.close()
        assert row is not None
        nonce, ciphertext, key_id, scope_id, format_version = row
        vector_key = memory._keyring.key_for_envelope(
            str(key_id),
            purpose=KEY_PURPOSE_VECTOR,
            envelope_version=int(format_version),
        )
        with pytest.raises(InvalidTag):
            AESGCM(vector_key).decrypt(
                bytes(nonce),
                bytes(ciphertext),
                scoped_aad(
                    object_type="payload",
                    scope_id=str(scope_id),
                    record_id=str(created["vine_id"]),
                    schema_version=int(format_version),
                    key_id=str(key_id),
                ),
            )
        assert memory.list_memories()[0]["payload"] == (
            "Payload and vector keys are independently derived."
        )


def test_v3_unknown_envelope_and_lost_key_fail_closed(tmp_path: Path) -> None:
    profile = "v3-fail-closed"
    with AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder()) as memory:
        created = memory.remember("fail closed", "Unknown formats must not vanish.")
        assert (
            memory.migrate_record_envelope_v3(confirm=True, batch_size=100)["state"]
            == "verified"
        )
        key_id = str(memory.doctor()["key_id"])

    profile_dir = tmp_path / profile
    key_path = profile_dir / "keys" / f"{key_id}.key"
    held_path = key_path.with_suffix(".held")
    key_path.rename(held_path)
    try:
        with pytest.raises(RuntimeError, match="key"):
            AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder())
    finally:
        held_path.rename(key_path)

    connection = sqlite3.connect(profile_dir / "payloads.db")
    try:
        connection.execute("PRAGMA ignore_check_constraints = ON")
        connection.execute(
            "UPDATE payloads SET format_version = 4 WHERE vine_id = ?",
            (str(created["vine_id"]),),
        )
        connection.commit()
    finally:
        connection.close()
    with pytest.raises(RuntimeError, match="integrity"):
        AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder())


def test_v3_key_rotation_preserves_envelope_and_blocks_early_retirement(
    tmp_path: Path,
) -> None:
    profile = "v3-rotation"
    payloads = [f"Rotation record {index}." for index in range(3)]
    with AgentMemory(tmp_path, profile=profile, embed=_SemanticEmbedder()) as memory:
        for payload in payloads:
            memory.remember("rotation", payload)
        assert (
            memory.migrate_record_envelope_v3(confirm=True, batch_size=100)["state"]
            == "verified"
        )
        first = memory.rotate_key(confirm=True, batch_size=1)
        assert first["remaining_key_references"] > 0
        assert first["lsh_index_rekeyed"] is True
        with pytest.raises(RuntimeError, match="fully verified"):
            memory.retire_previous_key(confirm_backups_accounted_for=True)
        for _attempt in range(20):
            rotation = memory.rotate_key(confirm=True, batch_size=2)
            if rotation["state"] == "verified":
                break
        else:  # pragma: no cover - bounded test profile must converge
            raise AssertionError("v3 key rotation did not converge")
        memory.retire_previous_key(confirm_backups_accounted_for=True)
        assert {record["payload"] for record in memory.list_memories()} == set(payloads)

    assert _versions(tmp_path / profile, "payloads") == {
        RECORD_ENVELOPE_V3: len(payloads)
    }


def test_profile_keyring_v3_rotation_increments_epoch_and_separates_keys(
    tmp_path: Path,
) -> None:
    profile_dir = tmp_path / "keyring-v3"
    profile_dir.mkdir(mode=0o700)
    keyring = ProfileKeyring(profile_dir, "local-user")
    keyring.enable_record_envelope_v3()
    first_id = keyring.active_key_id
    first_key = keyring.key_for_envelope(
        first_id,
        purpose=KEY_PURPOSE_PAYLOAD,
        envelope_version=RECORD_ENVELOPE_V3,
    )

    rotation = keyring.begin_rotation()
    second_id = rotation["to"]

    assert keyring.key_epoch(first_id) == 1
    assert keyring.key_epoch(second_id) == 2
    assert first_key != keyring.key_for_envelope(
        second_id,
        purpose=KEY_PURPOSE_PAYLOAD,
        envelope_version=RECORD_ENVELOPE_V3,
    )
