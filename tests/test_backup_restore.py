from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import threading
from pathlib import Path

import pytest

from echo_veil import backup as backup_module
from echo_veil.agent_memory import AgentMemory
from echo_veil.backup import BackupError
from echo_veil.record_envelope import RECORD_ENVELOPE_V2, RECORD_ENVELOPE_V3


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _migrate_v3(memory: AgentMemory, *, batch_size: int = 100) -> None:
    receipt = None
    if memory.doctor()["record_envelope"]["migration_state"] == "inactive" and any(
        memory._backup_counts().values()
    ):
        receipt = memory.backup_create(
            memory.profile_dir.parent / f".{memory.profile_dir.name}-pre-v3"
        )
    while True:
        result = memory.migrate_record_envelope_v3(
            confirm=True,
            batch_size=batch_size,
            verified_backup=receipt,
        )
        receipt = None
        if result["state"] == "verified":
            return


def _v3_memory(root: Path) -> AgentMemory:
    memory = AgentMemory(root)
    _migrate_v3(memory)
    return memory


def test_device_backup_verify_dry_run_and_actual_restore(tmp_path: Path) -> None:
    state = tmp_path / "source"
    archive = tmp_path / "backup"
    target = tmp_path / "target"
    with AgentMemory(state) as memory:
        first = memory.remember(
            "backup current fact",
            "The current restore marker is maple vector seven.",
        )
        memory.remember(
            "backup supporting fact",
            "The supporting restore marker is amber orbit.",
        )
        _migrate_v3(memory)
        receipt = memory.backup_create(archive)
        before = {
            name: _sha256(memory.profile_dir / name)
            for name in ("payloads.db", "echo-veil.db")
        }
        dry_run = memory.restore_dry_run(archive)
        after = {
            name: _sha256(memory.profile_dir / name)
            for name in ("payloads.db", "echo-veil.db")
        }
        assert before == after
        assert dry_run["profile_mutated"] is False
        assert dry_run["record_count"] == 2
        restored_receipt = memory.restore(archive, target, confirm=True)
        assert restored_receipt.backup_id == receipt.backup_id

    with AgentMemory(target, profile="restored") as restored:
        report = restored.doctor()
        assert report["payload_count"] == 2
        assert (
            restored.recall("maple vector seven")["results"][0]["vine_id"]
            == first["vine_id"]
        )


def test_backup_serializes_same_process_mutation_into_one_consistent_set(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    state = tmp_path / "source"
    archive = tmp_path / "backup"
    entered_snapshot = threading.Event()
    release_snapshot = threading.Event()
    mutation_started = threading.Event()
    mutation_finished = threading.Event()
    errors: list[BaseException] = []
    original_snapshot = backup_module.snapshot_sqlite
    snapshot_calls = 0

    def blocked_snapshot(connection: sqlite3.Connection, destination: Path) -> None:
        nonlocal snapshot_calls
        snapshot_calls += 1
        if snapshot_calls == 1:
            entered_snapshot.set()
            assert release_snapshot.wait(5.0)
        original_snapshot(connection, destination)

    with AgentMemory(state) as memory:
        memory.remember("before backup", "The backup boundary starts with one record.")
        _migrate_v3(memory)
        monkeypatch.setattr(backup_module, "snapshot_sqlite", blocked_snapshot)

        def create_backup() -> None:
            try:
                memory.backup_create(archive)
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)

        def mutate_profile() -> None:
            mutation_started.set()
            try:
                memory.remember(
                    "after backup",
                    "This record must wait until both snapshots are complete.",
                )
            except BaseException as exc:  # pragma: no cover - asserted below
                errors.append(exc)
            finally:
                mutation_finished.set()

        backup_thread = threading.Thread(target=create_backup)
        mutation_thread = threading.Thread(target=mutate_profile)
        backup_thread.start()
        assert entered_snapshot.wait(5.0)
        mutation_thread.start()
        assert mutation_started.wait(5.0)
        assert mutation_finished.wait(0.1) is False
        release_snapshot.set()
        backup_thread.join(5.0)
        mutation_thread.join(5.0)
        assert not backup_thread.is_alive()
        assert not mutation_thread.is_alive()
        assert errors == []
        assert memory.backup_verify(archive).record_count == 1
        assert memory.doctor()["payload_count"] == 2


def test_v2_backup_is_required_for_migration_and_never_grants_v3_readiness(
    tmp_path: Path,
) -> None:
    state = tmp_path / "source"
    archive = tmp_path / "pre-migration-backup"
    target = tmp_path / "v2-restore"
    with AgentMemory(state) as memory:
        created = memory.remember(
            "pre-migration recovery",
            "The version-two recovery marker is ivory compass.",
        )
        with pytest.raises(ValueError, match="pre-migration backup"):
            memory.migrate_record_envelope_v3(confirm=True)

        receipt = memory.backup_create(archive)
        assert receipt.record_envelope_version == RECORD_ENVELOPE_V2
        assert "record_envelope_version" not in receipt.as_dict()
        assert memory.doctor()["capabilities_v1"]["backup_verified"] is False

        restored = memory.restore(archive, target, confirm=True)
        assert restored.record_envelope_version == RECORD_ENVELOPE_V2
        while True:
            migration = memory.migrate_record_envelope_v3(
                confirm=True,
                verified_backup=receipt,
            )
            receipt = None
            if migration["state"] == "verified":
                break
        reverified = memory.backup_verify(archive)
        assert reverified.record_envelope_version == RECORD_ENVELOPE_V2
        assert memory.doctor()["capabilities_v1"]["backup_verified"] is False

        current = memory.backup_create(tmp_path / "v3-backup")
        assert current.record_envelope_version == RECORD_ENVELOPE_V3
        assert memory.doctor()["capabilities_v1"]["backup_verified"] is True

    with AgentMemory(target, profile="restored") as restored_memory:
        assert restored_memory.doctor()["record_envelope"]["migration_state"] == (
            "inactive"
        )
        assert restored_memory.list_memories()[0]["vine_id"] == created["vine_id"]


def test_restore_drill_opens_reconciles_and_removes_temporary_profile(
    tmp_path: Path,
) -> None:
    with AgentMemory(tmp_path / "state") as memory:
        memory.remember("drill", "The restore drill marker is cobalt lake.")
        _migrate_v3(memory)
        archive = tmp_path / "drill-backup"
        memory.backup_create(archive)
        result = memory.restore_drill(archive)

    assert result["restore_drill"] == "passed"
    assert result["logical_counts_reconciled"] is True
    assert result["temporary_profile_removed"] is True


def test_verified_backup_and_restore_evidence_survive_restart(tmp_path: Path) -> None:
    state = tmp_path / "state"
    archive = tmp_path / "backup"
    with AgentMemory(state) as memory:
        memory.remember("readiness", "Recovery evidence must survive a restart.")
        _migrate_v3(memory)
        memory.backup_create(archive)
        capabilities = memory.doctor()["capabilities_v1"]
        assert capabilities["backup_verified"] is True
        assert capabilities["restore_verified"] is False
        memory.restore_drill(archive)
        capabilities = memory.doctor()["capabilities_v1"]
        assert capabilities["backup_verified"] is True
        assert capabilities["restore_verified"] is True

    with AgentMemory(state) as restarted:
        capabilities = restarted.doctor()["capabilities_v1"]
        assert capabilities["backup_verified"] is True
        assert capabilities["restore_verified"] is True
        assert capabilities["rollback_detection"] == "none"


def test_restored_profile_keeps_prior_receipts_auditable_but_not_authoritative(
    tmp_path: Path,
) -> None:
    state = tmp_path / "source"
    first_archive = tmp_path / "first-backup"
    recovery_archive = tmp_path / "recovery-backup"
    target = tmp_path / "target"
    with AgentMemory(state) as memory:
        memory.remember(
            "receipt audit", "Prior receipts remain recovery evidence only."
        )
        _migrate_v3(memory)
        memory.backup_create(first_archive)
        memory.restore_drill(first_archive)
        assert memory.doctor()["capabilities_v1"]["restore_verified"] is True
        memory.backup_create(recovery_archive)
        memory.restore(recovery_archive, target, confirm=True)

    restored_profile = target / "restored"
    assert (restored_profile / "recovery-evidence" / "local-readiness.json").is_file()
    with AgentMemory(target, profile="restored") as restored:
        capabilities = restored.doctor()["capabilities_v1"]
        assert capabilities["backup_verified"] is False
        assert capabilities["restore_verified"] is False
        assert capabilities["host_boundary_verified"] is False


def test_tampered_readiness_evidence_fails_closed_without_hiding_diagnostic(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    archive = tmp_path / "backup"
    with AgentMemory(state) as memory:
        _migrate_v3(memory)
        memory.backup_create(archive)

    evidence = state / "default" / "local-readiness.json"
    encoded = bytearray(evidence.read_bytes())
    encoded[len(encoded) // 2] ^= 1
    evidence.write_bytes(encoded)
    evidence.chmod(0o600)

    with AgentMemory(state) as restarted:
        report = restarted.doctor()
        assert report["capabilities_v1"]["backup_verified"] is False
        assert (
            "EV-READINESS-EVIDENCE-INVALID"
            in (report["capabilities_v1"]["remediation_codes"])
        )


@pytest.mark.parametrize(
    "mutation",
    ["manifest", "ciphertext", "partial", "extra-root", "extra-file"],
)
def test_corrupt_or_partial_backup_is_rejected(
    tmp_path: Path,
    mutation: str,
) -> None:
    with AgentMemory(tmp_path / "state") as memory:
        memory.remember("corruption", "The protected backup marker is topaz.")
        _migrate_v3(memory)
        archive = tmp_path / "backup"
        memory.backup_create(archive)

        if mutation == "manifest":
            manifest_path = archive / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["generation"] += 1
            manifest_path.write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":")),
                encoding="utf-8",
            )
            manifest_path.chmod(0o600)
        elif mutation == "ciphertext":
            member = next((archive / "files").glob("*.bin"))
            payload = bytearray(member.read_bytes())
            payload[len(payload) // 2] ^= 0x01
            member.write_bytes(payload)
            member.chmod(0o600)
        elif mutation == "partial":
            next((archive / "files").glob("*.bin")).unlink()
        elif mutation == "extra-root":
            extra = archive / "unmanifested.bin"
            extra.write_bytes(b"untrusted")
            extra.chmod(0o600)
        else:
            extra = archive / "files" / "unmanifested.bin"
            extra.write_bytes(b"untrusted")
            extra.chmod(0o600)

        with pytest.raises((BackupError, FileNotFoundError)):
            memory.backup_verify(archive)


def test_wrong_profile_and_wrong_recovery_material_are_rejected(
    tmp_path: Path,
) -> None:
    archive = tmp_path / "backup"
    first = _v3_memory(tmp_path / "first")
    second = _v3_memory(tmp_path / "second")
    try:
        first.remember("profile one", "Only profile one can authenticate this backup.")
        first.backup_create(archive)
        with pytest.raises(BackupError):
            second.backup_verify(archive)
        with pytest.raises(BackupError):
            first.backup_verify(archive, recovery_key=b"x" * 32)
    finally:
        first.close()
        second.close()


def test_restore_refuses_existing_target_and_preserves_it(tmp_path: Path) -> None:
    target = tmp_path / "target"
    existing_profile = target / "restored"
    existing_profile.mkdir(mode=0o700, parents=True)
    marker = existing_profile / "owned.txt"
    marker.write_text("keep", encoding="utf-8")
    with AgentMemory(tmp_path / "state") as memory:
        memory.remember("target", "Existing restore targets are never replaced.")
        _migrate_v3(memory)
        archive = tmp_path / "backup"
        memory.backup_create(archive)
        with pytest.raises(FileExistsError):
            memory.restore(archive, target, confirm=True)
    assert marker.read_text(encoding="utf-8") == "keep"


def test_archive_copy_does_not_expose_memory_plaintext(tmp_path: Path) -> None:
    marker = b"private-backup-payload-marker-4821"
    with AgentMemory(tmp_path / "state") as memory:
        memory.remember("private backup", marker.decode("ascii"))
        _migrate_v3(memory)
        archive = tmp_path / "backup"
        memory.backup_create(archive)
    copied = tmp_path / "copied"
    shutil.copytree(archive, copied)
    assert all(
        marker not in path.read_bytes() for path in copied.rglob("*") if path.is_file()
    )


@pytest.mark.parametrize("replacement", ["symlink", "hardlink"])
def test_backup_member_link_attacks_are_rejected(
    tmp_path: Path,
    replacement: str,
) -> None:
    with AgentMemory(tmp_path / "state") as memory:
        memory.remember("link attack", "Backup members must remain pinned files.")
        _migrate_v3(memory)
        archive = tmp_path / "backup"
        memory.backup_create(archive)
        member = next((archive / "files").glob("*.bin"))
        outside = tmp_path / "saved-ciphertext.bin"
        shutil.copyfile(member, outside)
        outside.chmod(0o600)
        member.unlink()
        if replacement == "symlink":
            member.symlink_to(outside)
        else:
            os.link(outside, member)

        with pytest.raises(BackupError, match="identity|symbolic link"):
            memory.backup_verify(archive)
