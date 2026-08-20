"""Authenticated, profile-bound local-production evidence.

This store records only the output of completed verifiers. It is not an input
channel for RPC clients or environment variables, and it contains no payload,
topic, embedding, host path, or secret. The unsigned ``capabilities_v1`` view
may consume it; signed preflight-v2 receipts never do.
"""

from __future__ import annotations

import base64
import hmac
import json
import os
import re
from pathlib import Path
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ._json import strict_json_loads
from .agent_security import (
    ProfileKeyring,
    _atomic_write_json,
    _read_private_file_bytes,
)
from .backup import VerifiedBackup, profile_hash_for
from .local_readiness import LocalReadinessEvidence
from .record_envelope import (
    KEY_PURPOSE_BACKUP_MANIFEST,
    RECORD_ENVELOPE_V3,
    RECORD_ENVELOPE_V3_FEATURE,
)

READINESS_EVIDENCE_SCHEMA = "echo-veil-local-readiness-evidence-v1"
READINESS_EVIDENCE_ENVELOPE_SCHEMA = "echo-veil-local-readiness-evidence-envelope-v1"
READINESS_EVIDENCE_FILE = "local-readiness.json"
MAX_READINESS_EVIDENCE_BYTES = 64 * 1024

_BACKUP_ID = re.compile(r"[0-9a-f]{32}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_KEY_ID = re.compile(r"ev-[0-9a-f]{16}\Z")
_SCOPE_ID = re.compile(r"scope-[0-9a-f]{32}\Z")
_ROLLBACK_TIERS = frozenset({"none", "local-best-effort", "external-monotonic"})


class ReadinessEvidenceError(RuntimeError):
    """Authenticated local-readiness evidence is missing or corrupt."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_b64(value: object, *, label: str, expected: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 128 * 1024:
        raise ReadinessEvidenceError(f"{label} is invalid")
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (TypeError, ValueError) as exc:
        raise ReadinessEvidenceError(f"{label} is invalid") from exc
    if _b64(decoded) != value or (expected is not None and len(decoded) != expected):
        raise ReadinessEvidenceError(f"{label} is invalid")
    return decoded


def _empty_record() -> dict[str, object]:
    return {
        "artifact": None,
        "backup": None,
        "host_boundary": None,
        "restore": None,
        "schema": READINESS_EVIDENCE_SCHEMA,
    }


def _receipt_record(
    receipt: VerifiedBackup,
    *,
    rollback_detection: str,
) -> dict[str, object]:
    if rollback_detection not in _ROLLBACK_TIERS:
        raise ValueError("rollback-detection tier is invalid")
    return {
        "backup_id": receipt.backup_id,
        "generation": receipt.generation,
        "key_id": receipt.key_id,
        "manifest_sha256": receipt.manifest_sha256,
        "profile_hash": receipt.profile_hash,
        "record_count": receipt.record_count,
        "rollback_detection": rollback_detection,
        "verified_at": receipt.verified_at,
    }


def _validate_receipt_record(value: object, *, label: str) -> dict[str, object]:
    expected = {
        "backup_id",
        "generation",
        "key_id",
        "manifest_sha256",
        "profile_hash",
        "record_count",
        "rollback_detection",
        "verified_at",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ReadinessEvidenceError(f"{label} evidence fields are invalid")
    if (
        not isinstance(value["backup_id"], str)
        or _BACKUP_ID.fullmatch(value["backup_id"]) is None
        or not isinstance(value["key_id"], str)
        or _KEY_ID.fullmatch(value["key_id"]) is None
        or not isinstance(value["manifest_sha256"], str)
        or _DIGEST.fullmatch(value["manifest_sha256"]) is None
        or not isinstance(value["profile_hash"], str)
        or _DIGEST.fullmatch(value["profile_hash"]) is None
        or value["rollback_detection"] not in _ROLLBACK_TIERS
    ):
        raise ReadinessEvidenceError(f"{label} evidence binding is invalid")
    for name in ("generation", "record_count", "verified_at"):
        item = value[name]
        if isinstance(item, bool) or not isinstance(item, int) or item < 0:
            raise ReadinessEvidenceError(f"{label} evidence count is invalid")
    return dict(value)


class ReadinessEvidenceStore:
    """Persist verified evidence under a v3 purpose-separated profile key."""

    def __init__(self, profile_dir: Path, keyring: ProfileKeyring) -> None:
        self._profile_dir = profile_dir
        self._path = profile_dir / READINESS_EVIDENCE_FILE
        self._keyring = keyring

    def _key(self, key_id: str) -> bytes:
        return self._keyring.key_for_envelope(
            key_id,
            purpose=KEY_PURPOSE_BACKUP_MANIFEST,
            envelope_version=RECORD_ENVELOPE_V3,
        )

    def _aad(self, *, key_id: str, scope_id: str) -> bytes:
        return _canonical(
            {
                "format_version": RECORD_ENVELOPE_V3,
                "key_id": key_id,
                "schema": READINESS_EVIDENCE_ENVELOPE_SCHEMA,
                "scope_id": scope_id,
            }
        )

    def load_record(self) -> dict[str, object]:
        if not self._path.exists():
            return _empty_record()
        if not self._keyring.has_feature(RECORD_ENVELOPE_V3_FEATURE):
            raise ReadinessEvidenceError(
                "local-readiness evidence requires record-envelope v3"
            )
        raw = _read_private_file_bytes(
            self._path,
            label="local-readiness evidence",
            maximum=MAX_READINESS_EVIDENCE_BYTES,
        )
        try:
            envelope = strict_json_loads(raw)
        except Exception as exc:
            raise ReadinessEvidenceError(
                "local-readiness evidence is malformed"
            ) from exc
        expected = {
            "ciphertext_b64",
            "format_version",
            "key_id",
            "nonce_b64",
            "schema",
            "scope_id",
        }
        if not isinstance(envelope, dict) or set(envelope) != expected:
            raise ReadinessEvidenceError(
                "local-readiness evidence envelope fields are invalid"
            )
        key_id = envelope["key_id"]
        scope_id = envelope["scope_id"]
        if (
            envelope["schema"] != READINESS_EVIDENCE_ENVELOPE_SCHEMA
            or envelope["format_version"] != RECORD_ENVELOPE_V3
            or not isinstance(key_id, str)
            or _KEY_ID.fullmatch(key_id) is None
            or not isinstance(scope_id, str)
            or _SCOPE_ID.fullmatch(scope_id) is None
            or not hmac.compare_digest(scope_id, self._keyring.scope_id)
        ):
            raise ReadinessEvidenceError(
                "local-readiness evidence envelope binding is invalid"
            )
        try:
            plaintext = bytearray(
                AESGCM(self._key(key_id)).decrypt(
                    _decode_b64(
                        envelope["nonce_b64"],
                        label="local-readiness nonce",
                        expected=12,
                    ),
                    _decode_b64(
                        envelope["ciphertext_b64"],
                        label="local-readiness ciphertext",
                    ),
                    self._aad(key_id=key_id, scope_id=scope_id),
                )
            )
        except (InvalidTag, KeyError, ValueError) as exc:
            raise ReadinessEvidenceError(
                "local-readiness evidence authentication failed"
            ) from exc
        try:
            record = strict_json_loads(bytes(plaintext))
        finally:
            plaintext[:] = b"\0" * len(plaintext)
        expected_record = {
            "artifact",
            "backup",
            "host_boundary",
            "restore",
            "schema",
        }
        if (
            not isinstance(record, dict)
            or set(record) != expected_record
            or record["schema"] != READINESS_EVIDENCE_SCHEMA
            or record["artifact"] is not None
            or record["host_boundary"] is not None
        ):
            raise ReadinessEvidenceError("local-readiness evidence record is invalid")
        if record["backup"] is not None:
            record["backup"] = _validate_receipt_record(
                record["backup"], label="backup"
            )
        if record["restore"] is not None:
            record["restore"] = _validate_receipt_record(
                record["restore"], label="restore"
            )
        return dict(record)

    def _write_record(self, record: dict[str, object]) -> None:
        if not self._keyring.has_feature(RECORD_ENVELOPE_V3_FEATURE):
            raise RuntimeError("local-readiness evidence requires record-envelope v3")
        key_id = self._keyring.active_key_id
        scope_id = self._keyring.scope_id
        nonce = os.urandom(12)
        plaintext = _canonical(record)
        ciphertext = AESGCM(self._key(key_id)).encrypt(
            nonce,
            plaintext,
            self._aad(key_id=key_id, scope_id=scope_id),
        )
        _atomic_write_json(
            self._path,
            {
                "ciphertext_b64": _b64(ciphertext),
                "format_version": RECORD_ENVELOPE_V3,
                "key_id": key_id,
                "nonce_b64": _b64(nonce),
                "schema": READINESS_EVIDENCE_ENVELOPE_SCHEMA,
                "scope_id": scope_id,
            },
        )

    def record_backup(self, receipt: VerifiedBackup) -> None:
        self._validate_current_receipt(receipt)
        record = self.load_record()
        record["backup"] = _receipt_record(
            receipt,
            rollback_detection=receipt.rollback_detection,
        )
        # A different backup invalidates an earlier restore drill.
        restore = record.get("restore")
        if not isinstance(restore, dict) or restore.get("manifest_sha256") != (
            receipt.manifest_sha256
        ):
            record["restore"] = None
        self._write_record(record)

    def record_restore(self, receipt: VerifiedBackup) -> None:
        self._validate_current_receipt(receipt)
        record = self.load_record()
        backup = record.get("backup")
        if not isinstance(backup, dict) or backup.get("manifest_sha256") != (
            receipt.manifest_sha256
        ):
            raise ReadinessEvidenceError(
                "restore drill does not match the current verified backup"
            )
        record["restore"] = _receipt_record(
            receipt,
            rollback_detection=receipt.rollback_detection,
        )
        self._write_record(record)

    def invalidate_recovery(self) -> None:
        if not self._path.exists():
            return
        record = self.load_record()
        record["backup"] = None
        record["restore"] = None
        self._write_record(record)

    def evidence(self) -> LocalReadinessEvidence:
        record = self.load_record()
        backup = record.get("backup")
        restore = record.get("restore")
        current_key = self._keyring.active_key_id
        expected_hash = profile_hash_for(self._key(current_key), self._keyring.scope_id)
        backup_manifest = (
            backup.get("manifest_sha256") if isinstance(backup, dict) else None
        )
        backup_valid = bool(
            isinstance(backup, dict)
            and backup.get("key_id") == current_key
            and isinstance(backup.get("profile_hash"), str)
            and hmac.compare_digest(str(backup["profile_hash"]), expected_hash)
        )
        restore_valid = bool(
            backup_valid
            and isinstance(restore, dict)
            and restore.get("key_id") == current_key
            and restore.get("manifest_sha256") == backup_manifest
        )
        rollback_detection = (
            str(backup["rollback_detection"])
            if backup_valid and isinstance(backup, dict)
            else "none"
        )
        return LocalReadinessEvidence(
            artifact_verified=False,
            backup_verified=backup_valid,
            restore_verified=restore_valid,
            host_boundary_verified=False,
            key_custody=self._keyring.custody_provider,
            rollback_detection=rollback_detection,
        )

    def _validate_current_receipt(self, receipt: VerifiedBackup) -> None:
        if not isinstance(receipt, VerifiedBackup):
            raise TypeError("verified backup receipt is required")
        key_id = self._keyring.active_key_id
        expected_hash = profile_hash_for(self._key(key_id), self._keyring.scope_id)
        if receipt.key_id != key_id or not hmac.compare_digest(
            receipt.profile_hash,
            expected_hash,
        ):
            raise ReadinessEvidenceError(
                "verified backup does not match the active profile key"
            )


__all__ = [
    "READINESS_EVIDENCE_ENVELOPE_SCHEMA",
    "READINESS_EVIDENCE_FILE",
    "READINESS_EVIDENCE_SCHEMA",
    "ReadinessEvidenceError",
    "ReadinessEvidenceStore",
]
