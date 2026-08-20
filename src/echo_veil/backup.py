"""Authenticated, encrypted profile backup archives and restore verification.

Backups are directories rather than opaque tar files so every member can be
bounded and authenticated before it is opened.  Each source file is encrypted
in independent AES-GCM chunks.  The public manifest contains operational counts
and ciphertext metadata only; no memory payload, topic, embedding, key, or host
path is recorded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO, Iterator, Mapping

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ._json import strict_json_loads

BACKUP_SCHEMA = "echo-veil-backup-v1"
BACKUP_RECEIPT_SCHEMA = "echo-veil-backup-receipt-v1"
DEVICE_BOUND_RECOVERY = "device-bound"
PORTABLE_RECOVERY = "portable"
BACKUP_CHUNK_BYTES = 4 * 1024 * 1024
MAX_BACKUP_FILES = 64
MAX_BACKUP_FILE_BYTES = 4 * 1024 * 1024 * 1024
MAX_BACKUP_TOTAL_BYTES = 16 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 512 * 1024
MAX_MODEL_IDENTITY_BYTES = 2 * 1024

_BACKUP_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_LOGICAL_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,255}\Z")
_KEY_ID = re.compile(r"ev-[0-9a-f]{16}\Z")
_SCOPE_ID = re.compile(r"scope-[0-9a-f]{32}\Z")
_EXPECTED_COUNTS = frozenset(
    {"conflicts", "contracts", "records", "terms", "tombstones", "vectors"}
)
_ROLLBACK_TIERS = frozenset({"none", "local-best-effort", "external-monotonic"})


class BackupError(RuntimeError):
    """A backup or restore boundary could not be verified safely."""


class RollbackDetected(BackupError):
    """The selected archive is older than the configured monotonic authority."""


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_b64(value: object, *, label: str, expected: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise BackupError(f"{label} is invalid")
    try:
        raw = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise BackupError(f"{label} is invalid") from exc
    if _b64(raw) != value or (expected is not None and len(raw) != expected):
        raise BackupError(f"{label} is invalid")
    return raw


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _optional_digest(value: object, *, label: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise BackupError(f"{label} is invalid")
    return value


def _model_identity(value: object) -> str:
    if not isinstance(value, str):
        raise BackupError("backup model identity is invalid")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise BackupError("backup model identity is invalid") from exc
    if (
        not encoded
        or len(encoded) > MAX_MODEL_IDENTITY_BYTES
        or any(character < " " or character == "\x7f" for character in value)
    ):
        raise BackupError("backup model identity is invalid")
    return value


def _write_private(path: Path, payload: bytes) -> None:
    if not isinstance(payload, bytes):
        raise TypeError("private backup payload must be bytes")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | int(getattr(os, "O_CLOEXEC", 0))
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if isinstance(nofollow, int):
        flags |= nofollow
    descriptor = os.open(path, flags, 0o600)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError("backup file write was incomplete")
            offset += written
        os.fsync(descriptor)
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or int(information.st_nlink) != 1
            or (hasattr(os, "getuid") and int(information.st_uid) != int(os.getuid()))
            or stat.S_IMODE(information.st_mode) & 0o077
        ):
            raise PermissionError("backup file permissions are unsafe")
    finally:
        os.close(descriptor)


@contextmanager
def _open_private_reader(
    path: Path,
    maximum: int,
    *,
    label: str,
) -> Iterator[BinaryIO]:
    """Open one pinned owner-only regular file without following its final link."""

    before = path.stat(follow_symlinks=False)
    if stat.S_ISLNK(before.st_mode):
        raise BackupError(f"{label} must not be a symbolic link")
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if isinstance(nofollow, int):
        flags |= nofollow
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise BackupError(f"{label} could not be opened safely") from exc
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or int(information.st_nlink) != 1
            or (hasattr(os, "getuid") and int(information.st_uid) != int(os.getuid()))
            or stat.S_IMODE(information.st_mode) & 0o077
            or (before.st_dev, before.st_ino)
            != (information.st_dev, information.st_ino)
            or int(information.st_size) > maximum
        ):
            raise BackupError(f"{label} identity, ownership, or size is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as reader:
            yield reader
        after = os.fstat(descriptor)
        if (
            information.st_dev,
            information.st_ino,
            information.st_size,
            information.st_mtime_ns,
            information.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise BackupError(f"{label} changed while it was being read")
    finally:
        os.close(descriptor)


def _read_bounded(path: Path, maximum: int) -> bytes:
    with _open_private_reader(path, maximum, label="backup member") as reader:
        output = bytearray()
        while len(output) <= maximum:
            chunk = reader.read(min(64 * 1024, maximum + 1 - len(output)))
            if not chunk:
                break
            output.extend(chunk)
        if len(output) > maximum:
            raise BackupError("backup member exceeds its size limit")
        return bytes(output)


def _validate_private_directory(path: Path, *, label: str) -> None:
    information = path.stat(follow_symlinks=False)
    if (
        not stat.S_ISDIR(information.st_mode)
        or (hasattr(os, "getuid") and int(information.st_uid) != int(os.getuid()))
        or stat.S_IMODE(information.st_mode) & 0o077
    ):
        raise BackupError(f"{label} permissions or ownership are unsafe")


def _derive_keys(base_key: bytes, backup_id: str, domain: str) -> tuple[bytes, bytes]:
    if not isinstance(base_key, bytes) or len(base_key) != 32:
        raise ValueError("backup base key must contain exactly 32 bytes")
    if _BACKUP_ID.fullmatch(backup_id) is None:
        raise ValueError("backup ID is invalid")
    if domain not in {"profile", "portable"}:
        raise ValueError("backup key domain is invalid")
    material = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=hashlib.sha256(
            b"echo-veil-backup-v1-salt\0" + backup_id.encode("ascii")
        ).digest(),
        info=b"echo-veil-backup-v1\0" + domain.encode("ascii"),
    ).derive(base_key)
    return material[:32], material[32:]


def profile_hash_for(profile_key: bytes, scope_id: str) -> str:
    if not isinstance(profile_key, bytes) or len(profile_key) != 32:
        raise ValueError("backup profile key must contain exactly 32 bytes")
    if _SCOPE_ID.fullmatch(scope_id) is None:
        raise ValueError("backup scope ID is invalid")
    return (
        "sha256:"
        + hmac.new(
            profile_key,
            b"echo-veil-backup-profile-v1\0" + scope_id.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()
    )


def _file_aad(
    *,
    backup_id: str,
    profile_hash: str,
    logical_name: str,
    chunk_index: int,
    plaintext_size: int,
) -> bytes:
    return _canonical(
        {
            "backup_id": backup_id,
            "chunk_index": chunk_index,
            "logical_name": logical_name,
            "plaintext_size": plaintext_size,
            "profile_hash": profile_hash,
            "schema": BACKUP_SCHEMA,
        }
    )


@dataclass(frozen=True, slots=True)
class VerifiedBackup:
    """In-process proof that an archive was authenticated and fully decrypted."""

    backup_id: str
    generation: int
    manifest_sha256: str
    profile_hash: str
    key_id: str
    recovery_mode: str
    rollback_detection: str
    record_count: int
    artifact_digest: str | None
    host_authority_digest: str | None
    verified_at: int

    def __post_init__(self) -> None:
        if _BACKUP_ID.fullmatch(self.backup_id) is None:
            raise ValueError("verified backup ID is invalid")
        if _DIGEST.fullmatch(self.manifest_sha256) is None:
            raise ValueError("verified manifest digest is invalid")
        if _DIGEST.fullmatch(self.profile_hash) is None:
            raise ValueError("verified profile hash is invalid")
        if _KEY_ID.fullmatch(self.key_id) is None:
            raise ValueError("verified backup key ID is invalid")
        if self.recovery_mode not in {DEVICE_BOUND_RECOVERY, PORTABLE_RECOVERY}:
            raise ValueError("verified recovery mode is invalid")
        if self.rollback_detection not in _ROLLBACK_TIERS:
            raise ValueError("verified rollback-detection tier is invalid")
        for digest_value, label in (
            (self.artifact_digest, "verified artifact digest"),
            (self.host_authority_digest, "verified host-authority digest"),
        ):
            if digest_value is not None and _DIGEST.fullmatch(digest_value) is None:
                raise ValueError(f"{label} is invalid")
        if self.host_authority_digest is not None and self.artifact_digest is None:
            raise ValueError("verified host authority requires an artifact binding")
        for count in (self.generation, self.record_count, self.verified_at):
            if isinstance(count, bool) or not isinstance(count, int) or count < 0:
                raise ValueError("verified backup count is invalid")

    def as_dict(self) -> dict[str, object]:
        return {
            "backup_id": self.backup_id,
            "artifact_digest": self.artifact_digest,
            "generation": self.generation,
            "host_authority_digest": self.host_authority_digest,
            "key_id": self.key_id,
            "manifest_sha256": self.manifest_sha256,
            "profile_hash": self.profile_hash,
            "record_count": self.record_count,
            "recovery_mode": self.recovery_mode,
            "rollback_detection": self.rollback_detection,
            "schema": BACKUP_RECEIPT_SCHEMA,
            "verified_at": self.verified_at,
        }


def _validate_logical_name(value: object) -> str:
    if (
        not isinstance(value, str)
        or _LOGICAL_NAME.fullmatch(value) is None
        or value.startswith("/")
        or ".." in value.split("/")
    ):
        raise BackupError("backup logical name is invalid")
    return value


class BackupArchive:
    """Create, authenticate, decrypt, and verify one bounded backup archive."""

    @staticmethod
    def create(
        destination: Path,
        *,
        sources: Mapping[str, Path],
        profile_key: bytes,
        key_id: str,
        scope_id: str,
        key_epoch: int,
        generation: int,
        rollback_detection: str,
        counts: Mapping[str, int],
        model_identity: str,
        security_contract: str,
        record_envelope_version: int,
        artifact_digest: str | None,
        host_authority_digest: str | None,
        portable_recovery_key: bytes | None = None,
        portable_root_envelope: bytes | None = None,
        created_at: int | None = None,
        backup_id: str | None = None,
    ) -> VerifiedBackup:
        target = Path(os.path.abspath(os.fspath(destination)))
        if target.exists() or target.is_symlink():
            raise FileExistsError("backup destination already exists")
        if not target.parent.is_dir():
            raise FileNotFoundError("backup destination parent is missing")
        if not sources or len(sources) > MAX_BACKUP_FILES:
            raise ValueError("backup source count is invalid")
        if _KEY_ID.fullmatch(key_id) is None or _SCOPE_ID.fullmatch(scope_id) is None:
            raise ValueError("backup key binding is invalid")
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation <= 0
        ):
            raise ValueError("backup generation must be positive")
        if rollback_detection not in _ROLLBACK_TIERS:
            raise ValueError("rollback-detection tier is invalid")
        if (
            isinstance(key_epoch, bool)
            or not isinstance(key_epoch, int)
            or key_epoch <= 0
        ):
            raise ValueError("backup key epoch must be positive")
        if record_envelope_version != 3:
            raise ValueError("backup record-envelope version is invalid")
        if security_contract != "scoped-v2":
            raise ValueError("backup security contract is invalid")
        try:
            _model_identity(model_identity)
            artifact_digest = _optional_digest(
                artifact_digest,
                label="backup artifact digest",
            )
            host_authority_digest = _optional_digest(
                host_authority_digest,
                label="backup host-authority digest",
            )
        except BackupError as exc:
            raise ValueError(str(exc)) from exc
        if host_authority_digest is not None and artifact_digest is None:
            raise ValueError("backup host authority requires an artifact binding")
        recovery_mode = (
            PORTABLE_RECOVERY
            if portable_recovery_key is not None
            else DEVICE_BOUND_RECOVERY
        )
        if portable_recovery_key is not None:
            if len(portable_recovery_key) != 32 or portable_root_envelope is None:
                raise ValueError("portable recovery material is incomplete")
        elif portable_root_envelope is not None:
            raise ValueError("portable root envelope requires a recovery key")
        if set(counts) != _EXPECTED_COUNTS:
            raise ValueError("backup logical count fields are invalid")
        for name, value in counts.items():
            if (
                not isinstance(name, str)
                or not name
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise ValueError("backup logical count is invalid")
        backup_id = secrets.token_hex(16) if backup_id is None else backup_id
        if _BACKUP_ID.fullmatch(backup_id) is None:
            raise ValueError("backup ID is invalid")
        profile_hash = profile_hash_for(profile_key, scope_id)
        encryption_base = portable_recovery_key or profile_key
        encryption_domain = (
            "portable" if portable_recovery_key is not None else "profile"
        )
        encryption_key, _archive_mac_key = _derive_keys(
            encryption_base,
            backup_id,
            encryption_domain,
        )
        _unused_profile_enc, profile_mac_key = _derive_keys(
            profile_key,
            backup_id,
            "profile",
        )
        stage = target.parent / f".{target.name}.{secrets.token_hex(16)}.tmp"
        stage.mkdir(mode=0o700)
        os.chmod(stage, 0o700)
        files_dir = stage / "files"
        files_dir.mkdir(mode=0o700)
        os.chmod(files_dir, 0o700)
        file_entries: list[dict[str, object]] = []
        total_plaintext = 0
        try:
            for ordinal, logical_raw in enumerate(sorted(sources)):
                logical_name = _validate_logical_name(logical_raw)
                source = sources[logical_raw]
                ciphertext_name = f"{ordinal:03d}.bin"
                ciphertext_path = files_dir / ciphertext_name
                chunks: list[dict[str, object]] = []
                ciphertext_digest = hashlib.sha256()
                flags = (
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | int(getattr(os, "O_CLOEXEC", 0))
                )
                output_descriptor = os.open(ciphertext_path, flags, 0o600)
                try:
                    with _open_private_reader(
                        source,
                        MAX_BACKUP_FILE_BYTES,
                        label="backup source",
                    ) as reader:
                        information = os.fstat(reader.fileno())
                        total_plaintext += int(information.st_size)
                        if total_plaintext > MAX_BACKUP_TOTAL_BYTES:
                            raise BackupError(
                                "backup plaintext exceeds its total limit"
                            )
                        index = 0
                        while True:
                            plaintext = reader.read(BACKUP_CHUNK_BYTES)
                            if not plaintext:
                                break
                            nonce = os.urandom(12)
                            ciphertext = AESGCM(encryption_key).encrypt(
                                nonce,
                                plaintext,
                                _file_aad(
                                    backup_id=backup_id,
                                    profile_hash=profile_hash,
                                    logical_name=logical_name,
                                    chunk_index=index,
                                    plaintext_size=len(plaintext),
                                ),
                            )
                            offset = 0
                            while offset < len(ciphertext):
                                written = os.write(
                                    output_descriptor, ciphertext[offset:]
                                )
                                if written <= 0:
                                    raise OSError(
                                        "backup ciphertext write was incomplete"
                                    )
                                offset += written
                            ciphertext_digest.update(ciphertext)
                            chunks.append(
                                {
                                    "ciphertext_size": len(ciphertext),
                                    "nonce_b64": _b64(nonce),
                                    "plaintext_size": len(plaintext),
                                }
                            )
                            index += 1
                    os.fsync(output_descriptor)
                    output_information = os.fstat(output_descriptor)
                    if (
                        not stat.S_ISREG(output_information.st_mode)
                        or int(output_information.st_nlink) != 1
                        or stat.S_IMODE(output_information.st_mode) & 0o077
                    ):
                        raise BackupError("backup ciphertext file is unsafe")
                finally:
                    os.close(output_descriptor)
                file_entries.append(
                    {
                        "chunks": chunks,
                        "ciphertext_file": f"files/{ciphertext_name}",
                        "ciphertext_sha256": "sha256:" + ciphertext_digest.hexdigest(),
                        "logical_name": logical_name,
                        "plaintext_size": int(information.st_size),
                    }
                )
            now = int(time.time()) if created_at is None else created_at
            if isinstance(now, bool) or not isinstance(now, int) or now < 0:
                raise ValueError("backup creation time is invalid")
            manifest: dict[str, object] = {
                "artifact_digest": artifact_digest,
                "backup_id": backup_id,
                "counts": dict(sorted(counts.items())),
                "created_at": now,
                "files": file_entries,
                "generation": generation,
                "host_authority_digest": host_authority_digest,
                "key_epoch": key_epoch,
                "key_id": key_id,
                "model_identity": model_identity,
                "portable_root_envelope_b64": (
                    _b64(portable_root_envelope)
                    if portable_root_envelope is not None
                    else None
                ),
                "profile_hash": profile_hash,
                "record_envelope_version": record_envelope_version,
                "recovery_mode": recovery_mode,
                "rollback_detection": rollback_detection,
                "schema": BACKUP_SCHEMA,
                "scope_id": scope_id,
                "security_contract": security_contract,
                "wal_state": "captured-in-consistent-sqlite-snapshots",
            }
            manifest_bytes = _canonical(manifest)
            if len(manifest_bytes) > MAX_MANIFEST_BYTES:
                raise BackupError("backup manifest exceeds its size limit")
            _write_private(stage / "manifest.json", manifest_bytes)
            _write_private(
                stage / "profile.mac",
                hmac.new(profile_mac_key, manifest_bytes, hashlib.sha256)
                .hexdigest()
                .encode("ascii"),
            )
            if portable_recovery_key is not None:
                _unused_portable_enc, portable_mac_key = _derive_keys(
                    portable_recovery_key,
                    backup_id,
                    "portable",
                )
                _write_private(
                    stage / "portable.mac",
                    hmac.new(
                        portable_mac_key,
                        manifest_bytes,
                        hashlib.sha256,
                    )
                    .hexdigest()
                    .encode("ascii"),
                )
            os.rename(stage, target)
            parent_descriptor = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        return BackupArchive.verify(
            target,
            profile_key=profile_key,
            recovery_key=portable_recovery_key,
        )

    @staticmethod
    def _load_manifest(archive: Path) -> tuple[dict[str, Any], bytes]:
        root = Path(os.path.abspath(os.fspath(archive)))
        _validate_private_directory(root, label="backup archive")
        _validate_private_directory(root / "files", label="backup files directory")
        raw = _read_bounded(root / "manifest.json", MAX_MANIFEST_BYTES)
        decoded = strict_json_loads(raw)
        expected = {
            "artifact_digest",
            "backup_id",
            "counts",
            "created_at",
            "files",
            "generation",
            "host_authority_digest",
            "key_epoch",
            "key_id",
            "model_identity",
            "portable_root_envelope_b64",
            "profile_hash",
            "record_envelope_version",
            "recovery_mode",
            "rollback_detection",
            "schema",
            "scope_id",
            "security_contract",
            "wal_state",
        }
        if not isinstance(decoded, dict) or set(decoded) != expected:
            raise BackupError("backup manifest fields are invalid")
        if (
            decoded["schema"] != BACKUP_SCHEMA
            or _BACKUP_ID.fullmatch(str(decoded["backup_id"])) is None
        ):
            raise BackupError("backup manifest schema or ID is invalid")
        for name in ("created_at", "generation", "key_epoch"):
            value = decoded[name]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < (1 if name in {"generation", "key_epoch"} else 0)
            ):
                raise BackupError(f"backup {name.replace('_', ' ')} is invalid")
        if (
            not isinstance(decoded["key_id"], str)
            or _KEY_ID.fullmatch(decoded["key_id"]) is None
            or not isinstance(decoded["scope_id"], str)
            or _SCOPE_ID.fullmatch(decoded["scope_id"]) is None
            or not isinstance(decoded["profile_hash"], str)
            or _DIGEST.fullmatch(decoded["profile_hash"]) is None
        ):
            raise BackupError("backup key or profile binding is invalid")
        if decoded["recovery_mode"] not in {
            DEVICE_BOUND_RECOVERY,
            PORTABLE_RECOVERY,
        }:
            raise BackupError("backup recovery mode is invalid")
        if decoded["rollback_detection"] not in _ROLLBACK_TIERS:
            raise BackupError("backup rollback-detection tier is invalid")
        if (
            decoded["security_contract"] != "scoped-v2"
            or decoded["record_envelope_version"] != 3
            or decoded["wal_state"] != "captured-in-consistent-sqlite-snapshots"
        ):
            raise BackupError("backup security contract is invalid")
        _model_identity(decoded["model_identity"])
        artifact_digest = _optional_digest(
            decoded["artifact_digest"],
            label="backup artifact digest",
        )
        host_authority_digest = _optional_digest(
            decoded["host_authority_digest"],
            label="backup host-authority digest",
        )
        if host_authority_digest is not None and artifact_digest is None:
            raise BackupError("backup host authority requires an artifact binding")
        counts = decoded["counts"]
        if not isinstance(counts, dict) or set(counts) != _EXPECTED_COUNTS:
            raise BackupError("backup logical count fields are invalid")
        for name, value in counts.items():
            if (
                not isinstance(name, str)
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise BackupError("backup logical counts are invalid")
        portable_envelope = decoded["portable_root_envelope_b64"]
        if decoded["recovery_mode"] == DEVICE_BOUND_RECOVERY:
            if portable_envelope is not None:
                raise BackupError("device-bound backup has portable recovery data")
        else:
            envelope = _decode_b64(
                portable_envelope,
                label="portable root envelope",
            )
            if not 48 <= len(envelope) <= 256:
                raise BackupError("portable root envelope is invalid")
        if _canonical(decoded) != raw:
            raise BackupError("backup manifest is not canonical")
        return decoded, raw

    @staticmethod
    def verify(
        archive: Path,
        *,
        profile_key: bytes | None = None,
        recovery_key: bytes | None = None,
        expected_profile_hash: str | None = None,
        minimum_generation: int | None = None,
        output_dir: Path | None = None,
    ) -> VerifiedBackup:
        root = Path(os.path.abspath(os.fspath(archive)))
        manifest, raw = BackupArchive._load_manifest(root)
        backup_id = str(manifest["backup_id"])
        recovery_mode = str(manifest["recovery_mode"])
        if recovery_mode == DEVICE_BOUND_RECOVERY:
            if profile_key is None or recovery_key is not None:
                raise BackupError("device-bound verification requires the profile key")
            encryption_base = profile_key
            domain = "profile"
        elif recovery_mode == PORTABLE_RECOVERY:
            if recovery_key is None or len(recovery_key) != 32:
                raise BackupError("portable verification requires the recovery key")
            encryption_base = recovery_key
            domain = "portable"
        else:
            raise BackupError("backup recovery mode is invalid")
        expected_root_members = {"files", "manifest.json", "profile.mac"}
        if recovery_mode == PORTABLE_RECOVERY:
            expected_root_members.add("portable.mac")
        try:
            observed_root_members = {entry.name for entry in root.iterdir()}
        except OSError as exc:
            raise BackupError("backup archive inventory is unavailable") from exc
        if observed_root_members != expected_root_members:
            raise BackupError("backup archive contains unmanifested members")
        encryption_key, manifest_mac_key = _derive_keys(
            encryption_base,
            backup_id,
            domain,
        )
        tag_name = "portable.mac" if domain == "portable" else "profile.mac"
        stored_tag = _read_bounded(root / tag_name, 64).decode("ascii", errors="strict")
        expected_tag = hmac.new(manifest_mac_key, raw, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(stored_tag, expected_tag):
            raise BackupError("backup manifest authentication failed")
        profile_hash = str(manifest["profile_hash"])
        if _DIGEST.fullmatch(profile_hash) is None:
            raise BackupError("backup profile hash is invalid")
        if expected_profile_hash is not None and not hmac.compare_digest(
            expected_profile_hash,
            profile_hash,
        ):
            raise BackupError("backup belongs to another profile")
        generation = manifest["generation"]
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation <= 0
        ):
            raise BackupError("backup generation is invalid")
        if minimum_generation is not None and generation < minimum_generation:
            raise RollbackDetected(
                "backup generation is older than the monotonic authority"
            )
        files = manifest["files"]
        if not isinstance(files, list) or not files or len(files) > MAX_BACKUP_FILES:
            raise BackupError("backup file manifest is invalid")
        logical_names: set[str] = set()
        ciphertext_names: set[str] = set()
        total = 0
        cleanup_output = output_dir is None
        if output_dir is not None:
            output_root = Path(os.path.abspath(os.fspath(output_dir)))
            if output_root.exists():
                raise FileExistsError("restore output directory already exists")
            output_root.mkdir(mode=0o700)
            os.chmod(output_root, 0o700)
        else:
            output_root = Path(tempfile.mkdtemp(prefix="echo-veil-backup-verify-"))
            os.chmod(output_root, 0o700)
        try:
            for entry in files:
                if not isinstance(entry, dict) or set(entry) != {
                    "chunks",
                    "ciphertext_file",
                    "ciphertext_sha256",
                    "logical_name",
                    "plaintext_size",
                }:
                    raise BackupError("backup file entry is invalid")
                logical_name = _validate_logical_name(entry["logical_name"])
                if logical_name in logical_names:
                    raise BackupError("backup logical names are not unique")
                logical_names.add(logical_name)
                ciphertext_file = entry["ciphertext_file"]
                if not isinstance(ciphertext_file, str) or not re.fullmatch(
                    r"files/[0-9]{3}\.bin",
                    ciphertext_file,
                ):
                    raise BackupError("backup ciphertext reference is invalid")
                if ciphertext_file in ciphertext_names:
                    raise BackupError("backup ciphertext references are not unique")
                ciphertext_names.add(ciphertext_file)
                ciphertext_path = root / ciphertext_file
                chunks = entry["chunks"]
                if not isinstance(chunks, list) or len(chunks) > (
                    (MAX_BACKUP_FILE_BYTES + BACKUP_CHUNK_BYTES - 1)
                    // BACKUP_CHUNK_BYTES
                ):
                    raise BackupError("backup chunk manifest is invalid")
                plaintext_size = entry["plaintext_size"]
                if (
                    isinstance(plaintext_size, bool)
                    or not isinstance(plaintext_size, int)
                    or not 0 <= plaintext_size <= MAX_BACKUP_FILE_BYTES
                ):
                    raise BackupError("backup plaintext size is invalid")
                if bool(chunks) != bool(plaintext_size):
                    raise BackupError("backup chunks do not match plaintext size")
                total += plaintext_size
                if total > MAX_BACKUP_TOTAL_BYTES:
                    raise BackupError("backup plaintext exceeds its total limit")
                digest = hashlib.sha256()
                restored_size = 0
                writer: BinaryIO | None = None
                destination = output_root / logical_name
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                os.chmod(destination.parent, 0o700)
                writer_descriptor = os.open(
                    destination,
                    os.O_WRONLY
                    | os.O_CREAT
                    | os.O_EXCL
                    | int(getattr(os, "O_CLOEXEC", 0))
                    | int(getattr(os, "O_NOFOLLOW", 0)),
                    0o600,
                )
                writer = os.fdopen(writer_descriptor, "wb")
                try:
                    maximum_ciphertext = plaintext_size + (16 * len(chunks))
                    with _open_private_reader(
                        ciphertext_path,
                        maximum_ciphertext,
                        label="backup ciphertext",
                    ) as reader:
                        for index, chunk in enumerate(chunks):
                            if not isinstance(chunk, dict) or set(chunk) != {
                                "ciphertext_size",
                                "nonce_b64",
                                "plaintext_size",
                            }:
                                raise BackupError("backup chunk entry is invalid")
                            plain_length = chunk["plaintext_size"]
                            cipher_length = chunk["ciphertext_size"]
                            if (
                                isinstance(plain_length, bool)
                                or not isinstance(plain_length, int)
                                or not 0 < plain_length <= BACKUP_CHUNK_BYTES
                                or cipher_length != plain_length + 16
                            ):
                                raise BackupError("backup chunk size is invalid")
                            ciphertext = reader.read(cipher_length)
                            if len(ciphertext) != cipher_length:
                                raise BackupError("backup ciphertext is truncated")
                            digest.update(ciphertext)
                            try:
                                plaintext = AESGCM(encryption_key).decrypt(
                                    _decode_b64(
                                        chunk["nonce_b64"],
                                        label="backup chunk nonce",
                                        expected=12,
                                    ),
                                    ciphertext,
                                    _file_aad(
                                        backup_id=backup_id,
                                        profile_hash=profile_hash,
                                        logical_name=logical_name,
                                        chunk_index=index,
                                        plaintext_size=plain_length,
                                    ),
                                )
                            except InvalidTag as exc:
                                raise BackupError(
                                    "backup ciphertext authentication failed"
                                ) from exc
                            restored_size += len(plaintext)
                            if writer is not None:
                                writer.write(plaintext)
                        if reader.read(1):
                            raise BackupError("backup ciphertext has trailing bytes")
                    if restored_size != plaintext_size:
                        raise BackupError("backup plaintext size does not reconcile")
                    ciphertext_digest = entry["ciphertext_sha256"]
                    if (
                        not isinstance(ciphertext_digest, str)
                        or _DIGEST.fullmatch(ciphertext_digest) is None
                        or not hmac.compare_digest(
                            ciphertext_digest,
                            "sha256:" + digest.hexdigest(),
                        )
                    ):
                        raise BackupError("backup ciphertext digest is invalid")
                finally:
                    if writer is not None:
                        writer.flush()
                        os.fsync(writer.fileno())
                        writer.close()
            try:
                observed_ciphertext_names = {
                    f"files/{entry.name}" for entry in (root / "files").iterdir()
                }
            except OSError as exc:
                raise BackupError("backup file inventory is unavailable") from exc
            if observed_ciphertext_names != ciphertext_names:
                raise BackupError("backup files contain unmanifested members")
            BackupArchive._verify_sqlite_snapshots(output_root, manifest)
            counts = manifest["counts"]
            if not isinstance(counts, dict) or any(
                not isinstance(name, str)
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                for name, value in counts.items()
            ):
                raise BackupError("backup logical counts are invalid")
            record_count = int(counts.get("records", 0))
            return VerifiedBackup(
                backup_id=backup_id,
                generation=generation,
                manifest_sha256="sha256:" + hashlib.sha256(raw).hexdigest(),
                profile_hash=profile_hash,
                key_id=str(manifest["key_id"]),
                recovery_mode=recovery_mode,
                rollback_detection=str(manifest["rollback_detection"]),
                record_count=record_count,
                artifact_digest=_optional_digest(
                    manifest["artifact_digest"],
                    label="backup artifact digest",
                ),
                host_authority_digest=_optional_digest(
                    manifest["host_authority_digest"],
                    label="backup host-authority digest",
                ),
                verified_at=int(time.time()),
            )
        except Exception:
            shutil.rmtree(output_root, ignore_errors=True)
            raise
        finally:
            if cleanup_output:
                shutil.rmtree(output_root, ignore_errors=True)

    @staticmethod
    def _verify_sqlite_snapshots(root: Path, manifest: Mapping[str, Any]) -> None:
        for name in ("payloads.db", "echo-veil.db"):
            path = root / name
            if not path.is_file():
                raise BackupError("backup is missing a required SQLite snapshot")
            connection = sqlite3.connect(
                f"{path.absolute().as_uri()}?mode=ro&immutable=1",
                uri=True,
            )
            try:
                integrity = connection.execute("PRAGMA integrity_check").fetchone()
                if integrity != ("ok",):
                    raise BackupError("backup SQLite integrity check failed")
            finally:
                connection.close()
        counts = manifest.get("counts")
        if not isinstance(counts, Mapping):
            raise BackupError("backup logical counts are invalid")
        payload_connection = sqlite3.connect(
            f"{(root / 'payloads.db').absolute().as_uri()}?mode=ro&immutable=1",
            uri=True,
        )
        try:
            records = int(
                payload_connection.execute("SELECT COUNT(*) FROM payloads").fetchone()[
                    0
                ]
            )
            contracts = int(
                payload_connection.execute(
                    "SELECT COUNT(*) FROM adapter_metadata WHERE key LIKE 'memory_contract:%'"
                ).fetchone()[0]
            )
            vectors = int(
                payload_connection.execute(
                    "SELECT COUNT(*) FROM memory_vectors"
                ).fetchone()[0]
            )
            terms = int(
                payload_connection.execute(
                    "SELECT COUNT(*) FROM memory_terms"
                ).fetchone()[0]
            )
            tombstones = int(
                payload_connection.execute(
                    "SELECT COUNT(*) FROM deletion_tombstones"
                ).fetchone()[0]
            )
        finally:
            payload_connection.close()
        observed = {
            "contracts": contracts,
            "records": records,
            "terms": terms,
            "tombstones": tombstones,
            "vectors": vectors,
        }
        for name, value in observed.items():
            if counts.get(name) != value:
                raise BackupError(f"backup {name} count does not reconcile")

    @staticmethod
    def restore(
        archive: Path,
        target_profile: Path,
        *,
        scope: str,
        confirm: bool,
        profile_key: bytes | None = None,
        recovery_key: bytes | None = None,
        helper_path: Path | None = None,
        custody_provider: str = "macos-secure-enclave-v1",
        minimum_generation: int | None = None,
    ) -> VerifiedBackup:
        """Restore into a new profile directory and validate before publication."""

        if confirm is not True:
            raise ValueError("restore requires confirm=true")
        target = Path(os.path.abspath(os.fspath(target_profile)))
        if target.exists() or target.is_symlink():
            raise FileExistsError("restore target already exists")
        if not target.parent.is_dir():
            raise FileNotFoundError("restore target parent is missing")
        stage = target.parent / f".{target.name}.{secrets.token_hex(16)}.restore"
        provisioned_client: Any | None = None
        receipt: VerifiedBackup
        try:
            receipt = BackupArchive.verify(
                archive,
                profile_key=profile_key,
                recovery_key=recovery_key,
                minimum_generation=minimum_generation,
                output_dir=stage,
            )
            manifest, _raw = BackupArchive._load_manifest(archive)
            if receipt.recovery_mode == PORTABLE_RECOVERY:
                if recovery_key is None or helper_path is None:
                    raise BackupError(
                        "portable restore requires the recovery key and signed helper"
                    )
                from .agent_security import _atomic_write_json
                from .key_custody import (
                    MACOS_KEYCHAIN_V1,
                    MACOS_SECURE_ENCLAVE_V1,
                    CustodyDescriptor,
                    MacOSKeyCustodyClient,
                    executable_cdhash,
                    helper_identity,
                )

                if custody_provider not in {
                    MACOS_KEYCHAIN_V1,
                    MACOS_SECURE_ENCLAVE_V1,
                }:
                    raise ValueError("portable restore custody provider is invalid")
                encoded_root = manifest.get("portable_root_envelope_b64")
                envelope = _decode_b64(
                    encoded_root,
                    label="portable root envelope",
                )
                key_id = str(manifest["key_id"])
                helper = Path(os.path.abspath(os.fspath(helper_path)))
                helper_digest, helper_cdhash = helper_identity(helper)
                reference = f"evkc-{secrets.token_hex(16)}"
                descriptor = CustodyDescriptor(
                    provider=custody_provider,
                    reference=reference,
                    key_id=key_id,
                    helper_path=helper,
                    helper_sha256=helper_digest,
                    helper_cdhash=helper_cdhash,
                    peer_cdhash=executable_cdhash(),
                    state="active",
                )
                provisioned_client = MacOSKeyCustodyClient(descriptor, stage)
                imported = provisioned_client.import_portable(
                    envelope=envelope,
                    recovery_key=recovery_key,
                    context=b"echo-veil-portable-backup-v1\0"
                    + receipt.backup_id.encode("ascii"),
                )
                if imported != key_id:
                    raise BackupError("portable root key ID does not match the archive")
                custody_directory = stage / "custody"
                if custody_directory.exists():
                    shutil.rmtree(custody_directory)
                custody_directory.mkdir(mode=0o700)
                tag = provisioned_client.root_hmac(
                    b"echo-veil-key-custody-descriptor-v1\0"
                    + descriptor.authentication_message()
                ).hex()
                _atomic_write_json(
                    custody_directory / f"{reference}.json",
                    descriptor.as_dict(tag_hex=tag),
                )
                keys_directory = stage / "keys"
                if keys_directory.exists():
                    shutil.rmtree(keys_directory)
                keyring_path = stage / "keyring.json"
                keyring = strict_json_loads(_read_bounded(keyring_path, 64 * 1024))
                if not isinstance(keyring, dict):
                    raise BackupError("restored keyring manifest is invalid")
                keys = keyring.get("keys")
                if not isinstance(keys, dict) or set(keys) != {key_id}:
                    raise BackupError(
                        "portable restore requires one verified active key"
                    )
                entry = keys[key_id]
                epoch = entry.get("epoch") if isinstance(entry, dict) else None
                keys[key_id] = {
                    "epoch": epoch,
                    "provider": custody_provider,
                    "ref": reference,
                    "status": "active",
                }
                _atomic_write_json(keyring_path, keyring)

            from .agent_security import ProfileKeyring
            from .preflight_receipt import PreflightReceiptAuthority

            restored_keyring = ProfileKeyring(stage, scope, create=False)
            try:
                if restored_keyring.active_key_id != receipt.key_id:
                    raise BackupError("restored key identity does not reconcile")
                PreflightReceiptAuthority(stage, keyring=restored_keyring)
            finally:
                restored_keyring.close()
            runtime = stage / ".custody-runtime"
            if runtime.is_dir() and not any(runtime.iterdir()):
                runtime.rmdir()
            os.rename(stage, target)
            parent_descriptor = os.open(target.parent, os.O_RDONLY)
            try:
                os.fsync(parent_descriptor)
            finally:
                os.close(parent_descriptor)
        except Exception:
            if provisioned_client is not None:
                try:
                    provisioned_client.delete(confirm=True)
                except Exception:
                    pass
            shutil.rmtree(stage, ignore_errors=True)
            raise
        finally:
            if provisioned_client is not None:
                provisioned_client.close()
        return receipt


def snapshot_sqlite(connection: sqlite3.Connection, destination: Path) -> None:
    """Write one transactionally consistent, WAL-independent SQLite snapshot."""

    target = sqlite3.connect(destination)
    try:
        connection.backup(target)
        integrity = target.execute("PRAGMA integrity_check").fetchone()
        if integrity != ("ok",):
            raise BackupError("SQLite snapshot integrity check failed")
        target.execute("PRAGMA wal_checkpoint(TRUNCATE)")
        target.commit()
    finally:
        target.close()
    os.chmod(destination, 0o600)


__all__ = [
    "BACKUP_RECEIPT_SCHEMA",
    "BACKUP_SCHEMA",
    "DEVICE_BOUND_RECOVERY",
    "PORTABLE_RECOVERY",
    "BackupArchive",
    "BackupError",
    "RollbackDetected",
    "VerifiedBackup",
    "profile_hash_for",
    "snapshot_sqlite",
]
