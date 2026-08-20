from __future__ import annotations

import hashlib
import hmac
import json
import os
from pathlib import Path
import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from echo_veil import agent_security
from echo_veil.agent_memory import AgentMemory
from echo_veil.agent_security import KeyUnavailable, ProfileKeyring
from echo_veil.backup import RollbackDetected
from echo_veil.key_custody import (
    CustodyDescriptor,
    MACOS_SECURE_ENCLAVE_V1,
)
from echo_veil.record_envelope import (
    KEY_PURPOSE_PAYLOAD,
    RECORD_ENVELOPE_KEY_PURPOSES,
    derive_record_envelope_key,
)


class _FakeCustodyClient:
    roots: dict[str, bytes] = {}
    generations: dict[str, int] = {}

    def __init__(self, descriptor: CustodyDescriptor, _profile_dir: Path) -> None:
        self.descriptor = descriptor
        self.closed = False

    def import_root(self, root: bytes) -> str:
        if self.descriptor.reference in self.roots:
            raise RuntimeError("duplicate fake custody reference")
        self.roots[self.descriptor.reference] = root
        self.generations[self.descriptor.reference] = 0
        return agent_security.key_id_for(root)

    def _root(self) -> bytes:
        try:
            return self.roots[self.descriptor.reference]
        except KeyError as exc:
            raise RuntimeError("fake custody item is unavailable") from exc

    def derive_v3_key(
        self,
        *,
        profile_scope: str,
        scope_id: str,
        key_epoch: int,
        purpose: str,
    ) -> bytes:
        return derive_record_envelope_key(
            self._root(),
            profile_scope=profile_scope,
            scope_id=scope_id,
            key_epoch=key_epoch,
            purpose=purpose,
        )

    def root_hmac(self, message: bytes) -> bytes:
        return hmac.new(self._root(), message, hashlib.sha256).digest()

    def probe(self) -> dict[str, str]:
        return {
            "key_id": agent_security.key_id_for(self._root()),
            "provider": self.descriptor.provider,
            "reference": self.descriptor.reference,
        }

    def export_portable(self, *, recovery_key: bytes, context: bytes) -> bytes:
        nonce = os.urandom(12)
        return nonce + AESGCM(recovery_key).encrypt(nonce, self._root(), context)

    def import_portable(
        self,
        *,
        envelope: bytes,
        recovery_key: bytes,
        context: bytes,
    ) -> str:
        root = AESGCM(recovery_key).decrypt(envelope[:12], envelope[12:], context)
        return self.import_root(root)

    def generation(self) -> int:
        return self.generations.get(self.descriptor.reference, 0)

    def advance_generation(self, *, expected: int, new: int) -> int:
        if self.generation() != expected or new != expected + 1:
            raise RuntimeError("generation conflict")
        self.generations[self.descriptor.reference] = new
        return new

    def delete(self, *, confirm: bool) -> None:
        if confirm is not True:
            raise ValueError("confirmation required")
        self.roots.pop(self.descriptor.reference, None)
        self.generations.pop(self.descriptor.reference, None)

    def close(self) -> None:
        self.closed = True


@pytest.fixture
def fake_custody(monkeypatch: pytest.MonkeyPatch) -> type[_FakeCustodyClient]:
    _FakeCustodyClient.roots = {}
    _FakeCustodyClient.generations = {}
    monkeypatch.setattr(agent_security, "MacOSKeyCustodyClient", _FakeCustodyClient)
    monkeypatch.setattr(
        agent_security,
        "helper_identity",
        lambda _path: ("1" * 64, "2" * 40),
    )
    monkeypatch.setattr(agent_security, "executable_cdhash", lambda: "3" * 40)
    return _FakeCustodyClient


def _migrated_keyring(profile: Path) -> ProfileKeyring:
    keyring = ProfileKeyring(profile, "workspace:synthetic")
    keyring.enable_record_envelope_v3()
    return keyring


def _simulate_fresh_process(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(agent_security, "_PROCESS_INSTANCE_ID", os.urandom(16).hex())


def test_custody_descriptor_is_exact_and_path_bound(tmp_path: Path) -> None:
    descriptor = CustodyDescriptor(
        provider=MACOS_SECURE_ENCLAVE_V1,
        reference="evkc-" + "1" * 32,
        key_id="ev-" + "2" * 16,
        helper_path=(tmp_path / "helper").absolute(),
        helper_sha256="3" * 64,
        helper_cdhash="4" * 40,
        peer_cdhash="5" * 40,
    )
    encoded = descriptor.as_dict(tag_hex="6" * 64)
    parsed, tag = CustodyDescriptor.from_dict(encoded)
    assert parsed == descriptor
    assert tag == "6" * 64

    encoded["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        CustodyDescriptor.from_dict(encoded)


def test_custody_migration_requires_backup_and_keeps_raw_root_until_confirmed(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    keyring = _migrated_keyring(tmp_path / "profile")
    key_id = keyring.active_key_id
    root = keyring.active_key()
    expected = {
        purpose: keyring.key_for_envelope(
            key_id,
            purpose=purpose,
            envelope_version=3,
        )
        for purpose in RECORD_ENVELOPE_KEY_PURPOSES
    }

    with pytest.raises(ValueError, match="verified backup"):
        keyring.prepare_custody_migration(
            provider=MACOS_SECURE_ENCLAVE_V1,
            helper_path=helper,
            backup_verified=False,
        )

    prepared = keyring.prepare_custody_migration(
        provider=MACOS_SECURE_ENCLAVE_V1,
        helper_path=helper,
        backup_verified=True,
    )
    assert prepared["state"] == "prepared"
    assert keyring.custody_provider == "file-v1"
    assert keyring.raw_active_key_present is True

    activated = keyring.activate_custody_migration(confirm=True)
    assert activated == {
        "provider": MACOS_SECURE_ENCLAVE_V1,
        "state": "verified",
    }
    assert keyring.custody_provider == MACOS_SECURE_ENCLAVE_V1
    assert keyring.custody_state == "verified"
    assert keyring.raw_active_key_present is True
    with pytest.raises(KeyUnavailable, match="cannot be exported"):
        keyring.active_key()
    for purpose, derived in expected.items():
        assert hmac.compare_digest(
            keyring.key_for_envelope(
                key_id,
                purpose=purpose,
                envelope_version=3,
            ),
            derived,
        )

    with pytest.raises(RuntimeError, match="fresh-process verification"):
        keyring.retire_file_custody(confirm=True)

    # Reopening the object in the activation process is not a process restart.
    keyring.close()
    same_process = ProfileKeyring(tmp_path / "profile", "workspace:synthetic")
    assert (
        same_process.key_for_envelope(
            key_id,
            purpose=KEY_PURPOSE_PAYLOAD,
            envelope_version=3,
        )
        == expected[KEY_PURPOSE_PAYLOAD]
    )
    with pytest.raises(RuntimeError, match="fresh-process verification"):
        same_process.retire_file_custody(confirm=True)
    same_process.close()

    _simulate_fresh_process(monkeypatch)
    reopened = ProfileKeyring(tmp_path / "profile", "workspace:synthetic")
    retired = reopened.retire_file_custody(confirm=True)
    assert retired["state"] == "active"
    assert reopened.raw_active_key_present is False
    root_paths = tuple((tmp_path / "profile").rglob("*.key"))
    assert root_paths == ()
    assert root not in b"".join(
        path.read_bytes()
        for path in (tmp_path / "profile").rglob("*")
        if path.is_file() and path.stat().st_size <= 1_048_576
    )
    reopened.close()

    final = ProfileKeyring(tmp_path / "profile", "workspace:synthetic")
    assert final.custody_state == "active"
    assert (
        final.key_for_envelope(
            key_id,
            purpose=KEY_PURPOSE_PAYLOAD,
            envelope_version=3,
        )
        == expected[KEY_PURPOSE_PAYLOAD]
    )
    final.close()


def test_copy_without_device_item_fails_closed(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    profile = tmp_path / "profile"
    keyring = _migrated_keyring(profile)
    keyring.prepare_custody_migration(
        provider=MACOS_SECURE_ENCLAVE_V1,
        helper_path=helper,
        backup_verified=True,
    )
    keyring.activate_custody_migration(confirm=True)
    keyring.close()
    _simulate_fresh_process(monkeypatch)
    keyring = ProfileKeyring(profile, "workspace:synthetic")
    keyring.retire_file_custody(confirm=True)
    keyring.close()

    fake_custody.roots.clear()
    with pytest.raises(KeyUnavailable, match="descriptor is unavailable"):
        ProfileKeyring(profile, "workspace:synthetic")


def test_descriptor_tampering_fails_before_scope_use(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    profile = tmp_path / "profile"
    keyring = _migrated_keyring(profile)
    keyring.prepare_custody_migration(
        provider=MACOS_SECURE_ENCLAVE_V1,
        helper_path=helper,
        backup_verified=True,
    )
    keyring.activate_custody_migration(confirm=True)
    keyring.close()

    descriptor_path = next((profile / "custody").glob("evkc-*.json"))
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    descriptor["helper_sha256"] = "f" * 64
    descriptor_path.write_text(
        json.dumps(descriptor, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    descriptor_path.chmod(0o600)
    with pytest.raises(KeyUnavailable, match="authentication"):
        ProfileKeyring(profile, "workspace:synthetic")


def test_activation_receipt_tampering_blocks_file_root_retirement(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    profile = tmp_path / "profile"
    keyring = _migrated_keyring(profile)
    keyring.prepare_custody_migration(
        provider=MACOS_SECURE_ENCLAVE_V1,
        helper_path=helper,
        backup_verified=True,
    )
    keyring.activate_custody_migration(confirm=True)
    keyring.close()

    receipt_path = profile / "custody" / "activation-receipt.json"
    receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
    receipt["process_instance"] = "f" * 32
    receipt_path.write_text(
        json.dumps(receipt, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    receipt_path.chmod(0o600)

    _simulate_fresh_process(monkeypatch)
    reopened = ProfileKeyring(profile, "workspace:synthetic")
    with pytest.raises(KeyUnavailable, match="authentication"):
        reopened.retire_file_custody(confirm=True)
    assert reopened.raw_active_key_present is True
    reopened.close()


def test_file_root_retirement_resumes_after_descriptor_publication_crash(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    profile = tmp_path / "profile"
    keyring = _migrated_keyring(profile)
    keyring.prepare_custody_migration(
        provider=MACOS_SECURE_ENCLAVE_V1,
        helper_path=helper,
        backup_verified=True,
    )
    keyring.activate_custody_migration(confirm=True)
    keyring.close()

    _simulate_fresh_process(monkeypatch)
    reopened = ProfileKeyring(profile, "workspace:synthetic")
    original_unlink = agent_security._unlink_private_file

    def interrupt_key_unlink(path: Path, *, label: str) -> None:
        if path.suffix == ".key":
            raise OSError("simulated retirement interruption")
        original_unlink(path, label=label)

    monkeypatch.setattr(agent_security, "_unlink_private_file", interrupt_key_unlink)
    with pytest.raises(OSError, match="simulated retirement interruption"):
        reopened.retire_file_custody(confirm=True)
    assert reopened.raw_active_key_present is True
    reopened.close()

    monkeypatch.setattr(agent_security, "_unlink_private_file", original_unlink)
    resumed = ProfileKeyring(profile, "workspace:synthetic")
    assert resumed.retire_file_custody(confirm=True)["state"] == "active"
    assert resumed.raw_active_key_present is False
    assert not (profile / "custody" / "activation-receipt.json").exists()
    resumed.close()


def test_opaque_rotation_preserves_custody_and_retires_old_item(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    profile = tmp_path / "profile"
    keyring = _migrated_keyring(profile)
    keyring.prepare_custody_migration(
        provider=MACOS_SECURE_ENCLAVE_V1,
        helper_path=helper,
        backup_verified=True,
    )
    keyring.activate_custody_migration(confirm=True)
    keyring.close()
    _simulate_fresh_process(monkeypatch)
    keyring = ProfileKeyring(profile, "workspace:synthetic")
    keyring.retire_file_custody(confirm=True)
    old_reference = next(iter(fake_custody.roots))

    rotation = keyring.begin_rotation()
    assert rotation["state"] == "migrating"
    assert keyring.custody_provider == MACOS_SECURE_ENCLAVE_V1
    assert len(fake_custody.roots) == 2
    keyring.mark_rotation_verified()
    keyring.retire_previous_key(confirm_backups_accounted_for=True)
    assert old_reference not in fake_custody.roots
    assert len(fake_custody.roots) == 1
    assert tuple((profile / "keys").glob("*.key")) == ()
    keyring.close()


def test_agent_memory_custody_restart_recall_and_retirement(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    state = tmp_path / "state"
    with AgentMemory(state) as memory:
        created = memory.remember(
            "custody fixture",
            "The protected restart value is river seven.",
        )
        pre_migration = memory.backup_create(tmp_path / "record-envelope-v2-backup")
        while True:
            migration = memory.migrate_record_envelope_v3(
                confirm=True,
                batch_size=1,
                verified_backup=pre_migration,
            )
            pre_migration = None
            if migration["state"] == "verified":
                break
        backup = memory.backup_create(tmp_path / "custody-backup")
        custody = memory.migrate_key_custody(
            provider=MACOS_SECURE_ENCLAVE_V1,
            helper_path=helper,
            verified_backup=backup,
            confirm=True,
        )
        assert custody["state"] == "verified"
        assert custody["verified_records"] == 1
        assert custody["raw_root_retained"] is True

    _simulate_fresh_process(monkeypatch)
    with AgentMemory(state) as restarted:
        recalled = restarted.recall("river seven")
        assert recalled["results"][0]["vine_id"] == created["vine_id"]
        retired = restarted.retire_file_key_custody(confirm=True)
        assert retired["raw_root_retained"] is False

    with AgentMemory(state) as final:
        report = final.doctor()
        assert report["key_custody"] == {
            "provider": MACOS_SECURE_ENCLAVE_V1,
            "state": "active",
            "raw_key_files_present": False,
            "root_exportable_to_python": False,
            "host_compromise_protected": False,
        }
        assert (
            final.recall("river seven")["results"][0]["vine_id"] == created["vine_id"]
        )


def test_local_monotonic_custody_rejects_stale_backup_after_generation_advance(
    tmp_path: Path,
    fake_custody: type[_FakeCustodyClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    helper = (tmp_path / "signed-helper").absolute()
    helper.write_bytes(b"fixture")
    state = tmp_path / "state"
    custody_backup = tmp_path / "custody-backup"
    first_backup = tmp_path / "first-backup"
    second_backup = tmp_path / "second-backup"

    with AgentMemory(state) as memory:
        created = memory.remember(
            "rollback fixture",
            "The rollback marker is cedar orbit twenty-three.",
        )
        pre_migration = memory.backup_create(tmp_path / "record-envelope-v2-backup")
        while True:
            migration = memory.migrate_record_envelope_v3(
                confirm=True,
                batch_size=10,
                verified_backup=pre_migration,
            )
            pre_migration = None
            if migration["state"] == "verified":
                break
        verified = memory.backup_create(custody_backup)
        memory.migrate_key_custody(
            provider=MACOS_SECURE_ENCLAVE_V1,
            helper_path=helper,
            verified_backup=verified,
            confirm=True,
        )
        with pytest.raises(RuntimeError, match="fresh-process verification"):
            memory.retire_file_key_custody(confirm=True)

    _simulate_fresh_process(monkeypatch)
    with AgentMemory(state) as restarted:
        restarted.retire_file_key_custody(confirm=True)
        first = restarted.backup_create(
            first_backup,
            rollback_detection="local-best-effort",
        )
        restarted.forget(str(created["vine_id"]))
        second = restarted.backup_create(
            second_backup,
            rollback_detection="local-best-effort",
        )
        assert second.generation == first.generation + 1
        with pytest.raises(RollbackDetected):
            restarted.backup_verify(first_backup, record_evidence=False)
        with pytest.raises(RollbackDetected):
            restarted.restore_dry_run(first_backup)
