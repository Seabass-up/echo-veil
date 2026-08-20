"""Internal record-envelope versions and v3 key-domain separation.

This module is deliberately independent from the agent preflight protocol.
Record-envelope versions describe encrypted local state only; they are never
negotiated by, or exposed to, harness preflight consumers.
"""

from __future__ import annotations

import hashlib
import json
import re

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

RECORD_ENVELOPE_V2 = 2
RECORD_ENVELOPE_V3 = 3
SUPPORTED_RECORD_ENVELOPES = frozenset({RECORD_ENVELOPE_V2, RECORD_ENVELOPE_V3})
RECORD_ENVELOPE_V3_FEATURE = "record-envelope-v3"
RECORD_ENVELOPE_V3_ALGORITHM = "HKDF-SHA256/AES-256-GCM"

KEY_PURPOSE_PAYLOAD = "payload-encryption"
KEY_PURPOSE_VECTOR = "vector-encryption"
KEY_PURPOSE_SEMANTIC_CONTRACT = "semantic-contract-encryption"
KEY_PURPOSE_TOPIC_TOKEN = "topic-token"
KEY_PURPOSE_LEXICAL_TOKEN = "lexical-token"
KEY_PURPOSE_CONTENT_DIGEST = "content-digest"
KEY_PURPOSE_RECORD_INTEGRITY = "record-integrity-authentication"
KEY_PURPOSE_TOMBSTONE = "tombstone-authentication"
KEY_PURPOSE_LSH_INDEX = "lsh-projection-index-token"
KEY_PURPOSE_PREFLIGHT_SIGNING = "preflight-signing-key-protection"
KEY_PURPOSE_BACKUP_MANIFEST = "backup-manifest-authentication"

RECORD_ENVELOPE_KEY_PURPOSES = frozenset(
    {
        KEY_PURPOSE_PAYLOAD,
        KEY_PURPOSE_VECTOR,
        KEY_PURPOSE_SEMANTIC_CONTRACT,
        KEY_PURPOSE_TOPIC_TOKEN,
        KEY_PURPOSE_LEXICAL_TOKEN,
        KEY_PURPOSE_CONTENT_DIGEST,
        KEY_PURPOSE_RECORD_INTEGRITY,
        KEY_PURPOSE_TOMBSTONE,
        KEY_PURPOSE_LSH_INDEX,
        KEY_PURPOSE_PREFLIGHT_SIGNING,
        KEY_PURPOSE_BACKUP_MANIFEST,
    }
)

_SCOPE_ID = re.compile(r"scope-[0-9a-f]{32}\Z")


def derive_record_envelope_key(
    root_key: bytes,
    *,
    profile_scope: str,
    scope_id: str,
    key_epoch: int,
    purpose: str,
    envelope_version: int = RECORD_ENVELOPE_V3,
    algorithm: str = RECORD_ENVELOPE_V3_ALGORITHM,
) -> bytes:
    """Derive one v3 subkey with all security domains bound into HKDF.

    Version 2 intentionally continues using the historical root-key behavior;
    callers invoke this helper only for version 3 data.
    """

    if not isinstance(root_key, bytes) or len(root_key) != 32:
        raise ValueError("record-envelope root key must contain exactly 32 bytes")
    if (
        not isinstance(profile_scope, str)
        or not profile_scope
        or len(profile_scope) > 256
        or not profile_scope.isprintable()
    ):
        raise ValueError("record-envelope profile scope is invalid")
    if not isinstance(scope_id, str) or _SCOPE_ID.fullmatch(scope_id) is None:
        raise ValueError("record-envelope scope ID is invalid")
    if (
        isinstance(key_epoch, bool)
        or not isinstance(key_epoch, int)
        or not 1 <= key_epoch <= 2**31 - 1
    ):
        raise ValueError("record-envelope key epoch is invalid")
    if purpose not in RECORD_ENVELOPE_KEY_PURPOSES:
        raise ValueError("record-envelope key purpose is unsupported")
    if envelope_version != RECORD_ENVELOPE_V3:
        raise ValueError("record-envelope key derivation requires version 3")
    if algorithm != RECORD_ENVELOPE_V3_ALGORITHM:
        raise ValueError("record-envelope algorithm is unsupported")

    context = json.dumps(
        {
            "algorithm": algorithm,
            "envelope_version": envelope_version,
            "key_epoch": key_epoch,
            "profile_scope": profile_scope,
            "purpose": purpose,
            "scope_id": scope_id,
        },
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    salt = hashlib.sha256(
        b"echo-veil-record-envelope-v3-salt\0" + scope_id.encode("ascii")
    ).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"echo-veil-record-envelope-v3\0" + context,
    ).derive(root_key)
