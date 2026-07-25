"""Read-only equivalence verification for protected profile migrations."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import hashlib
import hmac
import os
from pathlib import Path
import secrets
import stat
import struct
from typing import Iterator

from .agent_memory import (
    LEGACY_PAYLOAD_SCHEMA_VERSION,
    PAYLOAD_SCHEMA_VERSION,
    ProfileKeyring,
    _EncryptedPayloadStore,
    _load_existing_key,
    _payload_database_version,
    _reject_symlink_components,
    _validate_profile,
    default_state_dir,
)
from .memory_layers import MemoryLayer, MemoryLayerContract


MAX_VERIFICATION_RECORDS = 1_000
MIGRATION_PROVENANCE = "migration:profile-transfer"


class ProfileMigrationVerificationError(RuntimeError):
    """A source and target profile could not be proven equivalent."""


@dataclass(frozen=True, slots=True)
class _RecordFingerprint:
    vine_id: str
    token: bytes
    superseded_by: str | None
    contract: MemoryLayerContract | None


@dataclass(frozen=True, slots=True)
class _ProfileSnapshot:
    security_schema: str
    records: tuple[_RecordFingerprint, ...]
    indexed_records: int
    unindexed_records: int


def verify_profile_migration(
    state_dir: str | os.PathLike[str] | None,
    *,
    source_profile: str,
    target_profile: str,
    source_scope: str = "local-user",
    target_scope: str = "local-user",
    allow_target_extras: bool = False,
) -> dict[str, object]:
    """Prove source content, time, links, and contracts exist in a target.

    Both payload stores are opened read-only. Plaintext is decrypted only long
    enough to derive process-local HMAC tokens and is never returned, logged, or
    written to a verification artifact.
    """

    if not isinstance(allow_target_extras, bool):
        raise TypeError("allow_target_extras must be a boolean")
    source_name = _validate_profile(source_profile)
    target_name = _validate_profile(target_profile)
    if source_name == target_name:
        raise ValueError("source and target profiles must be different")

    secret = secrets.token_bytes(32)
    source = _snapshot_profile(
        state_dir,
        profile=source_name,
        scope=source_scope,
        secret=secret,
    )
    target = _snapshot_profile(
        state_dir,
        profile=target_name,
        scope=target_scope,
        secret=secret,
    )
    secret = b""

    if not source.records:
        raise ProfileMigrationVerificationError("source profile is empty")
    if target.security_schema != "scoped-v2":
        raise ProfileMigrationVerificationError(
            "migration target must use scoped-v2 protection"
        )

    source_by_token = _records_by_token(source.records, label="source")
    target_by_token = _records_by_token(target.records, label="target")
    missing = set(source_by_token) - set(target_by_token)
    if missing:
        raise ProfileMigrationVerificationError(
            "target is missing one or more source records"
        )
    extras = set(target_by_token) - set(source_by_token)
    if extras and not allow_target_extras:
        raise ProfileMigrationVerificationError(
            "target contains records outside the verified migration"
        )

    source_to_target = {
        source_record.vine_id: target_by_token[token].vine_id
        for token, source_record in source_by_token.items()
    }
    target_by_id = {record.vine_id: record for record in target.records}
    supersession_edges = 0
    for token, source_record in source_by_token.items():
        target_record = target_by_token[token]
        expected_successor = (
            None
            if source_record.superseded_by is None
            else source_to_target.get(source_record.superseded_by)
        )
        if source_record.superseded_by is not None and expected_successor is None:
            raise ProfileMigrationVerificationError(
                "source supersession graph references an unknown record"
            )
        if target_record.superseded_by != expected_successor:
            raise ProfileMigrationVerificationError(
                "target supersession graph does not match the source"
            )
        if expected_successor is not None:
            supersession_edges += 1
        _verify_contract(
            source_record.contract,
            target_record.contract,
            source_to_target=source_to_target,
            target_by_id=target_by_id,
        )

    if target.unindexed_records != 0 or target.indexed_records != len(target.records):
        raise ProfileMigrationVerificationError("target retrieval index is incomplete")

    return {
        "verified": True,
        "source_profile": source_name,
        "target_profile": target_name,
        "source_security_schema": source.security_schema,
        "target_security_schema": target.security_schema,
        "source_records": len(source.records),
        "target_records": len(target.records),
        "matched_records": len(source.records),
        "target_extra_records": len(extras),
        "supersession_edges_matched": supersession_edges,
        "lifecycle_contracts_preserved": source.security_schema == "scoped-v2",
        "legacy_records_normalized_to_short_term": (
            source.security_schema == "legacy-v1"
        ),
        "target_all_records_shielded": True,
        "target_unindexed_records": 0,
        "plaintext_export_created": False,
    }


def _records_by_token(
    records: tuple[_RecordFingerprint, ...],
    *,
    label: str,
) -> dict[bytes, _RecordFingerprint]:
    indexed = {record.token: record for record in records}
    if len(indexed) != len(records):
        raise ProfileMigrationVerificationError(
            f"{label} contains duplicate canonical records"
        )
    return indexed


def _verify_contract(
    source: MemoryLayerContract | None,
    target: MemoryLayerContract | None,
    *,
    source_to_target: dict[str, str],
    target_by_id: dict[str, _RecordFingerprint],
) -> None:
    if target is None:
        raise ProfileMigrationVerificationError(
            "target record has no protected memory contract"
        )
    if source is None:
        if (
            target.layer != MemoryLayer.SHORT_TERM
            or MIGRATION_PROVENANCE not in target.provenance
            or target.promotion_history
            or target.logic_kind is not None
            or target.related_ids
        ):
            raise ProfileMigrationVerificationError(
                "legacy source was not normalized into reviewable Short-Term"
            )
        return

    mapped_related: list[str] = []
    for source_id in source.related_ids:
        target_id = source_to_target.get(source_id)
        if target_id is None or target_id not in target_by_id:
            raise ProfileMigrationVerificationError(
                "target contextual relationship is incomplete"
            )
        mapped_related.append(target_id)
    if (
        target.layer != source.layer
        or target.provenance != source.provenance
        or target.expires_at != source.expires_at
        or target.review_at != source.review_at
        or target.promotion_history != source.promotion_history
        or target.logic_kind != source.logic_kind
        or target.related_ids != tuple(mapped_related)
        or target.version != source.version
    ):
        raise ProfileMigrationVerificationError(
            "target protected memory contract does not match the source"
        )


def _snapshot_profile(
    state_dir: str | os.PathLike[str] | None,
    *,
    profile: str,
    scope: str,
    secret: bytes,
) -> _ProfileSnapshot:
    with _read_only_store(state_dir, profile=profile, scope=scope) as store:
        if len(store) > MAX_VERIFICATION_RECORDS:
            raise ProfileMigrationVerificationError(
                "profile exceeds the bounded verification record limit"
            )
        if store.quarantine_count() != 0:
            raise ProfileMigrationVerificationError(
                "profile contains quarantined records"
            )
        records = store.records_for_migration()
        if len(records) != len(store):
            raise ProfileMigrationVerificationError(
                "profile contains incomplete or unverified records"
            )
        fingerprints: list[_RecordFingerprint] = []
        for record in records:
            payload = store.get(record.vine_id)
            if payload is None:
                raise ProfileMigrationVerificationError(
                    "profile payload disappeared during verification"
                )
            try:
                token = _content_token(
                    secret,
                    record.topic,
                    payload,
                    record.effective_at,
                )
            finally:
                payload = ""
            contract = (
                store.get_memory_contract(record.vine_id)
                if store.metadata_protected
                else None
            )
            fingerprints.append(
                _RecordFingerprint(
                    vine_id=record.vine_id,
                    token=token,
                    superseded_by=record.superseded_by,
                    contract=contract,
                )
            )
        indexed, unindexed = store.retrieval_index_counts()
        return _ProfileSnapshot(
            security_schema=store.security_schema,
            records=tuple(fingerprints),
            indexed_records=indexed,
            unindexed_records=unindexed,
        )


def _content_token(
    secret: bytes,
    topic: str,
    payload: str,
    effective_at: float,
) -> bytes:
    digest = hmac.new(secret, digestmod=hashlib.sha256)
    for value in (topic.encode("utf-8"), payload.encode("utf-8")):
        digest.update(struct.pack(">I", len(value)))
        digest.update(value)
    digest.update(struct.pack(">d", effective_at))
    return digest.digest()


@contextmanager
def _read_only_store(
    state_dir: str | os.PathLike[str] | None,
    *,
    profile: str,
    scope: str,
) -> Iterator[_EncryptedPayloadStore]:
    base = default_state_dir() if state_dir is None else Path(state_dir).expanduser()
    profile_dir = (base / profile).absolute()
    _reject_symlink_components(profile_dir)
    if not profile_dir.is_dir():
        raise ProfileMigrationVerificationError("profile directory does not exist")
    info = profile_dir.stat()
    if os.name != "nt" and (
        info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise ProfileMigrationVerificationError(
            "profile directory must be current-user and owner-only"
        )
    payload_path = profile_dir / "payloads.db"
    version = _payload_database_version(payload_path)
    if version == LEGACY_PAYLOAD_SCHEMA_VERSION:
        store = _EncryptedPayloadStore(
            payload_path,
            legacy_key=_load_existing_key(profile_dir / "agent.key"),
            read_only=True,
        )
    elif version == PAYLOAD_SCHEMA_VERSION:
        store = _EncryptedPayloadStore(
            payload_path,
            keyring=ProfileKeyring(profile_dir, scope, create=False),
            read_only=True,
        )
    else:
        raise ProfileMigrationVerificationError(
            "profile payload schema is unsupported or uninitialized"
        )
    try:
        yield store
    finally:
        store.close()
