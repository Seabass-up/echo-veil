from __future__ import annotations

import json
from multiprocessing import get_context
import os
from pathlib import Path
import secrets

import pytest

from echo_veil.agent_memory import AgentMemory
from echo_veil.backup import RollbackDetected
from echo_veil.key_custody import (
    CustodyDescriptor,
    MacOSKeyCustodyClient,
)


def _helper() -> Path:
    configured = os.environ.get("ECHO_VEIL_MACOS_CUSTODY_HELPER")
    if not configured:
        pytest.skip("native macOS custody helper is not configured")
    path = Path(configured).resolve()
    if not path.is_file():
        pytest.fail("configured native custody helper is missing")
    return path


def _delete_profile_items(profile: Path) -> None:
    custody = profile / "custody"
    for path in custody.glob("evkc-*.json") if custody.is_dir() else ():
        descriptor, _tag = CustodyDescriptor.from_dict(
            json.loads(path.read_text(encoding="utf-8"))
        )
        client = MacOSKeyCustodyClient(descriptor, profile)
        try:
            client.delete(confirm=True)
        finally:
            client.close()


@pytest.mark.skipif(os.name != "posix", reason="native helper requires macOS")
def test_native_secure_enclave_portable_restore_and_rollback_detection(
    tmp_path: Path,
) -> None:
    helper = _helper()
    recovery_key = secrets.token_bytes(32)
    source_state = tmp_path / "source"
    replacement_state = tmp_path / "replacement"
    source_profile = source_state / "default"
    replacement_profile = replacement_state / "restored"
    custody_backup = tmp_path / "custody-backup"
    first_backup = tmp_path / "portable-first"
    second_backup = tmp_path / "portable-second"
    try:
        with AgentMemory(source_state) as memory:
            created = memory.remember(
                "native custody fixture",
                "The native replacement marker is quartz harbor nineteen.",
            )
            pre_migration = memory.backup_create(tmp_path / "record-envelope-v2-backup")
            while True:
                result = memory.migrate_record_envelope_v3(
                    confirm=True,
                    batch_size=10,
                    verified_backup=pre_migration,
                )
                pre_migration = None
                if result["state"] == "verified":
                    break
            verified = memory.backup_create(custody_backup)
            migration = memory.migrate_key_custody(
                provider="macos-secure-enclave-v1",
                helper_path=helper,
                verified_backup=verified,
                confirm=True,
            )
            assert migration["raw_root_retained"] is True

        process = get_context("spawn").Process(
            target=_retire_file_custody_in_spawned_process,
            args=(os.fspath(source_state),),
        )
        process.start()
        process.join(timeout=60)
        if process.is_alive():
            process.terminate()
            process.join(timeout=10)
            pytest.fail("fresh-process custody retirement timed out")
        assert process.exitcode == 0

        with AgentMemory(source_state) as memory:
            first = memory.backup_create(
                first_backup,
                recovery_mode="portable",
                recovery_key=recovery_key,
                rollback_detection="local-best-effort",
            )
            memory.forget(str(created["vine_id"]))
            second = memory.backup_create(
                second_backup,
                recovery_mode="portable",
                recovery_key=recovery_key,
                rollback_detection="local-best-effort",
            )
            assert second.generation == first.generation + 1
            with pytest.raises(RollbackDetected):
                memory.backup_verify(first_backup, recovery_key=recovery_key)
            restored = memory.restore(
                second_backup,
                replacement_state,
                recovery_key=recovery_key,
                helper_path=helper,
                confirm=True,
            )
            assert restored.generation == second.generation

        with AgentMemory(replacement_state, profile="restored") as replacement:
            report = replacement.doctor()
            assert report["key_custody"]["provider"] == "macos-secure-enclave-v1"
            assert report["payload_count"] == 0
    finally:
        for profile in (source_profile, replacement_profile):
            try:
                _delete_profile_items(profile)
            except Exception:
                # The test must not hide cleanup failure when a profile exists.
                if profile.exists():
                    raise


def _retire_file_custody_in_spawned_process(state: str) -> None:
    with AgentMemory(Path(state)) as memory:
        memory.retire_file_key_custody(confirm=True)
