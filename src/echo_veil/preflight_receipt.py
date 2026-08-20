"""Short-lived signed receipts for one protected host model turn."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import re
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Callable

from cryptography.exceptions import InvalidSignature
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ._json import strict_json_loads
from .agent_security import (
    AES_GCM_NONCE_BYTES,
    ProfileKeyring,
    _atomic_write_json,
    _read_private_file_bytes,
    _write_new_key,
)
from .record_envelope import (
    KEY_PURPOSE_PREFLIGHT_SIGNING,
    RECORD_ENVELOPE_V3,
    RECORD_ENVELOPE_V3_FEATURE,
)

PREFLIGHT_RECEIPT_SCHEMA = "echo-veil-preflight-v2"
PREFLIGHT_SIGNING_KEY_FILE = "preflight-ed25519.key"
PREFLIGHT_SIGNING_KEY_SCHEMA = "echo-veil-preflight-signing-key-v1"
DEFAULT_RECEIPT_LIFETIME_SECONDS = 90.0
MAX_RECEIPT_LIFETIME_SECONDS = 120.0
MAX_RECEIPT_BYTES = 32_768
MAX_CONSUMED_RECEIPTS = 4_096
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}\Z")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HEX_ID = re.compile(r"[0-9a-f]{32}\Z")
_CAPABILITIES = frozenset(
    {
        "semantic_recall",
        "contextual_logic",
        "mutations_allowed",
        "inferential_recall",
    }
)
_CLAIM_FIELDS = {
    "allowed_capabilities",
    "ambiguity",
    "artifact_authority_id",
    "authority",
    "authority_id",
    "conflict",
    "context_digest",
    "embedding_model_digest",
    "expires_at_ms",
    "host",
    "issued_at_ms",
    "model_digest",
    "nonce_b64",
    "preflight_id",
    "profile",
    "query_digest",
    "query_source",
    "schema",
    "scope",
    "semantic_mode",
    "session_id",
    "tool_manifest_digest",
    "turn_id",
}


def _signing_key_aad(
    *,
    key_id: str,
    scope_id: str,
    envelope_version: int,
) -> bytes:
    return canonical_json(
        {
            "envelope_version": envelope_version,
            "key_id": key_id,
            "schema": PREFLIGHT_SIGNING_KEY_SCHEMA,
            "scope_id": scope_id,
        }
    )


def _protect_signing_key(keyring: ProfileKeyring, raw: bytes) -> dict[str, object]:
    if not isinstance(raw, bytes) or len(raw) != 32:
        raise ValueError("preflight signing key has an invalid size")
    if not keyring.has_feature(RECORD_ENVELOPE_V3_FEATURE):
        raise RuntimeError("preflight signing-key protection requires envelope v3")
    key_id = keyring.active_key_id
    nonce = os.urandom(AES_GCM_NONCE_BYTES)
    aad = _signing_key_aad(
        key_id=key_id,
        scope_id=keyring.scope_id,
        envelope_version=RECORD_ENVELOPE_V3,
    )
    ciphertext = AESGCM(
        keyring.key_for_envelope(
            key_id,
            purpose=KEY_PURPOSE_PREFLIGHT_SIGNING,
            envelope_version=RECORD_ENVELOPE_V3,
        )
    ).encrypt(nonce, raw, aad)
    return {
        "ciphertext_b64": _b64(ciphertext),
        "envelope_version": RECORD_ENVELOPE_V3,
        "key_id": key_id,
        "nonce_b64": _b64(nonce),
        "schema": PREFLIGHT_SIGNING_KEY_SCHEMA,
        "scope_id": keyring.scope_id,
    }


def _reveal_signing_key(keyring: ProfileKeyring, value: object) -> bytes:
    if not isinstance(value, dict) or set(value) != {
        "ciphertext_b64",
        "envelope_version",
        "key_id",
        "nonce_b64",
        "schema",
        "scope_id",
    }:
        raise ValueError("protected preflight signing key is invalid")
    if (
        value["schema"] != PREFLIGHT_SIGNING_KEY_SCHEMA
        or value["envelope_version"] != RECORD_ENVELOPE_V3
        or value["scope_id"] != keyring.scope_id
        or value["key_id"] not in keyring.key_ids
    ):
        raise ValueError("protected preflight signing key binding is invalid")
    key_id = str(value["key_id"])
    nonce = _decode_b64(value["nonce_b64"], "preflight signing nonce", 12)
    ciphertext = _decode_b64(
        value["ciphertext_b64"],
        "protected preflight signing key",
        48,
    )
    try:
        raw = AESGCM(
            keyring.key_for_envelope(
                key_id,
                purpose=KEY_PURPOSE_PREFLIGHT_SIGNING,
                envelope_version=RECORD_ENVELOPE_V3,
            )
        ).decrypt(
            nonce,
            ciphertext,
            _signing_key_aad(
                key_id=key_id,
                scope_id=keyring.scope_id,
                envelope_version=RECORD_ENVELOPE_V3,
            ),
        )
    except InvalidTag as exc:
        raise ValueError(
            "protected preflight signing key authentication failed"
        ) from exc
    if len(raw) != 32:
        raise ValueError("protected preflight signing key size is invalid")
    return raw


def protect_preflight_signing_key(
    profile_dir: str | os.PathLike[str],
    keyring: ProfileKeyring,
) -> bool:
    """Migrate or rewrap the receipt key under the active v3 purpose key."""

    path = Path(profile_dir).absolute() / PREFLIGHT_SIGNING_KEY_FILE
    raw_file = _read_private_file_bytes(
        path,
        label="preflight signing key",
        maximum=2_048,
    )
    try:
        decoded = strict_json_loads(raw_file)
    except Exception:
        decoded = None
    if isinstance(decoded, dict):
        raw = _reveal_signing_key(keyring, decoded)
        if decoded.get("key_id") == keyring.active_key_id:
            return False
    elif len(raw_file) == 32:
        raw = raw_file
    else:
        raise ValueError("preflight signing key is invalid")
    _atomic_write_json(path, _protect_signing_key(keyring, raw))
    return True


def preflight_signing_key_status(
    profile_dir: str | os.PathLike[str],
    keyring: ProfileKeyring | None,
) -> str:
    path = Path(profile_dir).absolute() / PREFLIGHT_SIGNING_KEY_FILE
    raw = _read_private_file_bytes(
        path,
        label="preflight signing key",
        maximum=2_048,
    )
    try:
        decoded = strict_json_loads(raw)
    except Exception:
        return "legacy-raw" if len(raw) == 32 else "invalid"
    if keyring is None:
        return "protected-unavailable"
    _reveal_signing_key(keyring, decoded)
    return "v3-purpose-protected"


def canonical_json(value: object) -> bytes:
    return json.dumps(
        _canonical_value(value),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _canonical_value(value: object) -> object:
    if value is None or isinstance(value, (str, bool, int)):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("canonical JSON numbers must be finite")
        return int(value) if value.is_integer() else value
    if isinstance(value, Mapping):
        if any(not isinstance(key, str) for key in value):
            raise TypeError("canonical JSON object keys must be strings")
        return {key: _canonical_value(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_canonical_value(item) for item in value]
    raise TypeError("value is not canonical JSON data")


def sha256_digest(value: bytes | str) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else value
    if not isinstance(raw, bytes):
        raise TypeError("digest input must be bytes or text")
    return f"sha256:{hashlib.sha256(raw).hexdigest()}"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_b64(value: object, label: str, expected_size: int | None = None) -> bytes:
    if not isinstance(value, str) or not value or "=" in value or len(value) > 512:
        raise ValueError(f"{label} is invalid")
    try:
        encoded = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
    except Exception as exc:
        raise ValueError(f"{label} is invalid") from exc
    if not hmac.compare_digest(_b64(decoded), value):
        raise ValueError(f"{label} is invalid")
    if expected_size is not None and len(decoded) != expected_size:
        raise ValueError(f"{label} is invalid")
    return decoded


def _bounded_id(value: object, label: str) -> str:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


def _timestamp_ms(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{label} is invalid")
    if value < 0:
        raise ValueError(f"{label} is invalid")
    return value


class PreflightReceiptAuthority:
    """Issue receipts from one owner-only profile signing key."""

    def __init__(
        self,
        profile_dir: str | os.PathLike[str],
        *,
        create: bool = False,
        keyring: ProfileKeyring | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        path = Path(profile_dir).absolute() / PREFLIGHT_SIGNING_KEY_FILE
        try:
            stored = _read_private_file_bytes(
                path,
                label="preflight signing key",
                maximum=2_048,
            )
        except Exception:
            if not create:
                raise
            raw_new = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            if keyring is not None and keyring.has_feature(RECORD_ENVELOPE_V3_FEATURE):
                _atomic_write_json(path, _protect_signing_key(keyring, raw_new))
                stored = _read_private_file_bytes(
                    path,
                    label="preflight signing key",
                    maximum=2_048,
                )
            else:
                _write_new_key(path, raw_new)
                stored = raw_new
        try:
            decoded = strict_json_loads(stored)
        except Exception:
            decoded = None
        if isinstance(decoded, dict):
            if keyring is None:
                raise RuntimeError(
                    "protected preflight signing key requires the profile keyring"
                )
            raw = _reveal_signing_key(keyring, decoded)
        elif len(stored) == 32:
            raw = stored
            if (
                create
                and keyring is not None
                and keyring.has_feature(RECORD_ENVELOPE_V3_FEATURE)
            ):
                _atomic_write_json(path, _protect_signing_key(keyring, raw))
        else:
            raise ValueError("preflight signing key is invalid")
        self._private_key = Ed25519PrivateKey.from_private_bytes(raw)
        self._public_bytes = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.authority_id = sha256_digest(
            b"echo-veil-preflight-authority-v2\0" + self._public_bytes
        )
        self._clock = clock

    @property
    def public_key_b64(self) -> str:
        return _b64(self._public_bytes)

    def issue(
        self,
        *,
        host: str,
        profile: str,
        scope: str,
        session_id: str,
        turn_id: str,
        query_source: str,
        query_digest: str,
        context_digest: str,
        embedding_model_digest: str,
        model_digest: str,
        tool_manifest_digest: str,
        artifact_authority_id: str,
        ambiguity: bool,
        conflict: bool,
        allowed_capabilities: list[str],
        lifetime_seconds: float = DEFAULT_RECEIPT_LIFETIME_SECONDS,
    ) -> dict[str, object]:
        if (
            isinstance(lifetime_seconds, bool)
            or not isinstance(lifetime_seconds, (int, float))
            or not 0.0 < float(lifetime_seconds) <= MAX_RECEIPT_LIFETIME_SECONDS
        ):
            raise ValueError("receipt lifetime is invalid")
        if not isinstance(ambiguity, bool) or not isinstance(conflict, bool):
            raise TypeError("receipt ambiguity and conflict flags must be booleans")
        if (
            not isinstance(allowed_capabilities, list)
            or len(allowed_capabilities) > len(_CAPABILITIES)
            or len(set(allowed_capabilities)) != len(allowed_capabilities)
            or any(value not in _CAPABILITIES for value in allowed_capabilities)
        ):
            raise ValueError("receipt capabilities are invalid")
        issued_at_ms = int(self._clock() * 1_000)
        lifetime_ms = int(math.ceil(float(lifetime_seconds) * 1_000))
        claims: dict[str, object] = {
            "allowed_capabilities": sorted(allowed_capabilities),
            "ambiguity": ambiguity,
            "artifact_authority_id": _digest(
                artifact_authority_id, "artifact authority ID"
            ),
            "authority": "echo-veil",
            "authority_id": self.authority_id,
            "conflict": conflict,
            "context_digest": _digest(context_digest, "context digest"),
            "embedding_model_digest": _digest(
                embedding_model_digest, "embedding model digest"
            ),
            "expires_at_ms": issued_at_ms + lifetime_ms,
            "host": _bounded_id(host, "host"),
            "issued_at_ms": issued_at_ms,
            "model_digest": _digest(model_digest, "model digest"),
            "nonce_b64": _b64(os.urandom(32)),
            "preflight_id": os.urandom(16).hex(),
            "profile": _bounded_id(profile, "profile"),
            "query_digest": _digest(query_digest, "query digest"),
            "query_source": _bounded_id(query_source, "query source"),
            "schema": PREFLIGHT_RECEIPT_SCHEMA,
            "scope": _bounded_id(scope, "scope"),
            "semantic_mode": "semantic",
            "session_id": _bounded_id(session_id, "session ID"),
            "tool_manifest_digest": _digest(
                tool_manifest_digest, "tool manifest digest"
            ),
            "turn_id": _bounded_id(turn_id, "turn ID"),
        }
        encoded = canonical_json(claims)
        return {
            "claims": claims,
            "public_key_b64": self.public_key_b64,
            "signature_b64": _b64(self._private_key.sign(encoded)),
        }


class PreflightReceiptVerifier:
    """Verify and consume a signed receipt exactly once for one host turn."""

    def __init__(
        self,
        public_key: bytes,
        *,
        expected_authority_id: str,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not isinstance(public_key, bytes) or len(public_key) != 32:
            raise ValueError("preflight public key must contain 32 bytes")
        self._public_key = Ed25519PublicKey.from_public_bytes(public_key)
        calculated = sha256_digest(b"echo-veil-preflight-authority-v2\0" + public_key)
        if not hmac.compare_digest(
            calculated,
            _digest(expected_authority_id, "authority ID"),
        ):
            raise ValueError("preflight authority ID does not match its public key")
        self._authority_id = calculated
        self._clock = clock
        self._consumed: dict[str, int] = {}

    @classmethod
    def from_public_key_b64(
        cls,
        public_key_b64: str,
        *,
        expected_authority_id: str,
        clock: Callable[[], float] = time.time,
    ) -> PreflightReceiptVerifier:
        return cls(
            _decode_b64(public_key_b64, "preflight public key", 32),
            expected_authority_id=expected_authority_id,
            clock=clock,
        )

    def verify_and_consume(
        self,
        value: object,
        *,
        context: object,
        query: str,
        host: str,
        profile: str,
        scope: str,
        session_id: str,
        turn_id: str,
        query_source: str,
        embedding_model_digest: str,
        model_digest: str,
        tool_manifest_digest: str,
        artifact_authority_id: str,
    ) -> dict[str, object]:
        if not isinstance(value, Mapping) or set(value) != {
            "claims",
            "public_key_b64",
            "signature_b64",
        }:
            raise ValueError("preflight receipt is invalid")
        public_bytes = _decode_b64(value["public_key_b64"], "preflight public key", 32)
        expected_public = self._public_key.public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        if not hmac.compare_digest(public_bytes, expected_public):
            raise ValueError("preflight receipt uses an unapproved authority")
        claims_value = value["claims"]
        if not isinstance(claims_value, Mapping) or set(claims_value) != _CLAIM_FIELDS:
            raise ValueError("preflight receipt claims are invalid")
        claims = dict(claims_value)
        encoded = canonical_json(claims)
        if len(encoded) > MAX_RECEIPT_BYTES:
            raise ValueError("preflight receipt exceeds its size limit")
        try:
            self._public_key.verify(
                _decode_b64(value["signature_b64"], "preflight signature", 64),
                encoded,
            )
        except InvalidSignature as exc:
            raise ValueError("preflight receipt signature is invalid") from exc
        now_ms = int(self._clock() * 1_000)
        issued_at_ms = _timestamp_ms(claims["issued_at_ms"], "receipt issue time")
        expires_at_ms = _timestamp_ms(claims["expires_at_ms"], "receipt expiry")
        if (
            issued_at_ms > now_ms + 5_000
            or expires_at_ms <= now_ms
            or expires_at_ms < issued_at_ms
            or expires_at_ms - issued_at_ms > int(MAX_RECEIPT_LIFETIME_SECONDS * 1_000)
        ):
            raise ValueError("preflight receipt is expired or invalid")
        expected = {
            "artifact_authority_id": _digest(
                artifact_authority_id, "artifact authority ID"
            ),
            "authority": "echo-veil",
            "authority_id": self._authority_id,
            "context_digest": sha256_digest(canonical_json(context)),
            "host": _bounded_id(host, "host"),
            "embedding_model_digest": _digest(
                embedding_model_digest,
                "embedding model digest",
            ),
            "model_digest": _digest(model_digest, "model digest"),
            "profile": _bounded_id(profile, "profile"),
            "query_digest": sha256_digest(query.strip()),
            "query_source": _bounded_id(query_source, "query source"),
            "schema": PREFLIGHT_RECEIPT_SCHEMA,
            "scope": _bounded_id(scope, "scope"),
            "semantic_mode": "semantic",
            "session_id": _bounded_id(session_id, "session ID"),
            "tool_manifest_digest": _digest(
                tool_manifest_digest, "tool manifest digest"
            ),
            "turn_id": _bounded_id(turn_id, "turn ID"),
        }
        for field, expected_value in expected.items():
            if claims.get(field) != expected_value:
                raise ValueError(f"preflight receipt {field} binding is invalid")
        evidence = dict(context) if isinstance(context, Mapping) else {}
        recall = evidence.get("recall")
        if not isinstance(recall, Mapping):
            raise ValueError("preflight receipt context binding is invalid")
        ambiguity = recall.get("ranking_ambiguous") is True
        conflict = recall.get("competing_memory_detected") is True
        expected_capabilities = ["semantic_recall"]
        if evidence.get("contextual_logic") is not None:
            expected_capabilities.append("contextual_logic")
        expected_context_bindings: tuple[tuple[str, object], ...] = (
            ("ambiguity", ambiguity),
            ("conflict", conflict),
            ("allowed_capabilities", sorted(expected_capabilities)),
        )
        for claim_name, context_value in expected_context_bindings:
            if claims.get(claim_name) != context_value:
                raise ValueError(f"preflight receipt {claim_name} binding is invalid")
        preflight_id = claims.get("preflight_id")
        if not isinstance(preflight_id, str) or _HEX_ID.fullmatch(preflight_id) is None:
            raise ValueError("preflight receipt ID is invalid")
        _decode_b64(claims.get("nonce_b64"), "preflight nonce", 32)
        capabilities = claims.get("allowed_capabilities")
        if (
            not isinstance(capabilities, list)
            or len(capabilities) > len(_CAPABILITIES)
            or len(set(capabilities)) != len(capabilities)
            or any(value not in _CAPABILITIES for value in capabilities)
        ):
            raise ValueError("preflight receipt capabilities are invalid")
        if preflight_id in self._consumed:
            raise ValueError("preflight receipt was already consumed")
        self._consumed = {
            receipt_id: expiry
            for receipt_id, expiry in self._consumed.items()
            if expiry > now_ms
        }
        if len(self._consumed) >= MAX_CONSUMED_RECEIPTS:
            raise RuntimeError("preflight receipt replay cache is full")
        self._consumed[preflight_id] = expires_at_ms
        return claims


def decode_receipt_json(value: bytes) -> dict[str, object]:
    if not isinstance(value, bytes) or not 0 < len(value) <= MAX_RECEIPT_BYTES:
        raise ValueError("preflight receipt JSON is invalid")
    decoded = strict_json_loads(value)
    if not isinstance(decoded, dict):
        raise ValueError("preflight receipt JSON is invalid")
    return decoded
