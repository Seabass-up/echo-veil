"""Local profile cryptography for the concrete agent-memory adapter.

This module is intentionally narrower than Echo Veil's production enclave
boundary.  It provides a fail-closed, owner-only local AES-GCM profile with:

* opaque scope identifiers;
* record-, schema-, scope-, and key-bound associated data;
* a non-secret key manifest whose entries reference owner-only key files; and
* multi-key reads so an interrupted key rotation remains recoverable.

The manifest never contains key material.  Python cannot guarantee complete
zeroization of immutable objects, so callers must still treat the process and
its operating-system account as trusted while a profile is open.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import json
import math
import os
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from numpy.typing import NDArray

from ._json import strict_json_loads
from .vectors import as_vector, cosine_similarity

KEYRING_SCHEMA_VERSION = 1
SCOPED_VECTOR_SCHEMA_VERSION = 2
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
AES_256_KEY_BYTES = 32
MAX_VECTOR_ELEMENTS = 4_000_000
MAX_SCOPED_VECTOR_JSON_BYTES = 64 * 1024 * 1024
MAX_SCOPE_CHARS = 256
KEY_ID_PREFIX = "ev-"
_KEY_ID_RE = re.compile(r"ev-[0-9a-f]{16}\Z")
_RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SCOPE_ID_RE = re.compile(r"scope-[0-9a-f]{32}\Z")
_KEY_REF_RE = re.compile(r"(?:agent\.key|keys/ev-[0-9a-f]{16}\.key)\Z")


class KeyUnavailable(RuntimeError):
    """A referenced profile key is missing or cannot be used safely."""


def normalize_scope(value: str) -> str:
    if not isinstance(value, str):
        raise TypeError("authorization scope must be a string")
    normalized = " ".join(value.strip().split())
    if (
        not normalized
        or len(normalized) > MAX_SCOPE_CHARS
        or not normalized.isprintable()
        or any(ord(character) < 0x20 for character in normalized)
    ):
        raise ValueError("authorization scope must be a bounded printable string")
    return normalized


def key_id_for(key: bytes) -> str:
    if not isinstance(key, bytes) or len(key) != AES_256_KEY_BYTES:
        raise ValueError("profile key must contain exactly 32 bytes")
    digest = hashlib.sha256(b"echo-veil-key-id-v1\0" + key).hexdigest()
    return f"{KEY_ID_PREFIX}{digest[:16]}"


def _scope_binding(key: bytes, scope: str, scope_id: str) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(b"echo-veil-scope-binding-v1\0")
    digest.update(scope_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(scope.encode("utf-8"))
    return digest.hexdigest()


def _validate_key_id(value: object) -> str:
    if not isinstance(value, str) or _KEY_ID_RE.fullmatch(value) is None:
        raise ValueError("profile key ID is invalid")
    return value


def _validate_record_id(value: object) -> str:
    if not isinstance(value, str) or _RECORD_ID_RE.fullmatch(value) is None:
        raise ValueError("record ID is invalid")
    return value


def _validate_scope_id(value: object) -> str:
    if not isinstance(value, str) or _SCOPE_ID_RE.fullmatch(value) is None:
        raise ValueError("scope ID is invalid")
    return value


def _reject_symlink_components(path: Path) -> None:
    absolute = path.absolute()
    for component in (absolute, *absolute.parents):
        if component.is_symlink():
            raise ValueError("security-sensitive paths must not contain symbolic links")


def _secure_directory(path: Path) -> Path:
    _reject_symlink_components(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("profile key directory must be a regular directory")
    if os.name != "nt":
        mode = stat.S_IMODE(path.stat().st_mode)
        if mode & 0o077:
            raise PermissionError("profile key directory must be owner-only")
        os.chmod(path, 0o700)
    return path


def _require_owner_file(path: Path, label: str) -> None:
    try:
        _reject_symlink_components(path)
    except ValueError as exc:
        raise KeyUnavailable(f"{label} path is unsafe") from exc
    if path.is_symlink() or not path.is_file():
        raise KeyUnavailable(f"{label} is missing")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise KeyUnavailable(f"{label} permissions are too broad")


def _read_key(path: Path) -> bytes:
    _require_owner_file(path, "profile key")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise KeyUnavailable("profile key is not a regular file")
        raw = os.read(descriptor, AES_256_KEY_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(raw) != AES_256_KEY_BYTES:
        raise KeyUnavailable("profile key has an invalid length")
    return raw


def _write_new_key(path: Path, key: bytes) -> None:
    if len(key) != AES_256_KEY_BYTES:
        raise ValueError("profile key must contain exactly 32 bytes")
    _reject_symlink_components(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        _write_all(descriptor, key)
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _reject_symlink_components(path)
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    try:
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, 0o600)
        _write_all(descriptor, encoded)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _write_all(descriptor: int, value: bytes) -> None:
    view = memoryview(value)
    offset = 0
    while offset < len(view):
        written = os.write(descriptor, view[offset:])
        if written <= 0:
            raise OSError("security-sensitive file write was incomplete")
        offset += written


class ProfileKeyring:
    """Permission-checked key references for one authorization scope."""

    def __init__(self, profile_dir: Path, scope: str, *, create: bool = True) -> None:
        self.profile_dir = _secure_directory(profile_dir)
        self.scope = normalize_scope(scope)
        self.manifest_path = self.profile_dir / "keyring.json"
        self._keys: dict[str, bytes] = {}
        self._manifest: dict[str, Any]
        if self.manifest_path.exists():
            self._manifest = self._load_manifest()
        elif create:
            self._manifest = self._create_manifest()
        else:
            raise KeyUnavailable("profile key manifest is missing")
        self._load_referenced_keys()
        self._verify_scope_binding()

    @property
    def active_key_id(self) -> str:
        return _validate_key_id(self._manifest["active_key_id"])

    @property
    def scope_id(self) -> str:
        return _validate_scope_id(self._manifest["scope_id"])

    @property
    def rotation_state(self) -> dict[str, str] | None:
        raw = self._manifest.get("rotation")
        if raw is None:
            return None
        if not isinstance(raw, dict) or set(raw) != {"from", "to", "state"}:
            raise KeyUnavailable("profile key manifest rotation state is invalid")
        source = _validate_key_id(raw["from"])
        target = _validate_key_id(raw["to"])
        state = raw["state"]
        if state not in {"migrating", "verified"}:
            raise KeyUnavailable("profile key manifest rotation state is invalid")
        return {"from": source, "to": target, "state": str(state)}

    @property
    def key_ids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def key(self, key_id: str) -> bytes:
        clean_id = _validate_key_id(key_id)
        try:
            return self._keys[clean_id]
        except KeyError as exc:
            raise KeyUnavailable("required profile key is unavailable") from exc

    def active_key(self) -> bytes:
        return self.key(self.active_key_id)

    def begin_rotation(self) -> dict[str, str]:
        current = self.rotation_state
        if current is not None:
            if current["state"] == "migrating":
                return current
            raise RuntimeError(
                "the previous key rotation must be retired or acknowledged first"
            )
        source = self.active_key_id
        while True:
            key = AESGCM.generate_key(bit_length=256)
            target = key_id_for(key)
            if target not in self._keys:
                break
        relative_ref = f"keys/{target}.key"
        key_path = self.profile_dir / relative_ref
        _secure_directory(key_path.parent)
        _write_new_key(key_path, key)
        manifest = copy.deepcopy(self._manifest)
        keys = manifest["keys"]
        if not isinstance(keys, dict):
            raise KeyUnavailable("profile key manifest is invalid")
        keys[source]["status"] = "decrypt-only"
        keys[target] = {"ref": relative_ref, "status": "active"}
        manifest["active_key_id"] = target
        manifest["rotation"] = {
            "from": source,
            "to": target,
            "state": "migrating",
        }
        manifest["scope_binding"] = _scope_binding(
            key,
            self.scope,
            self.scope_id,
        )
        try:
            _atomic_write_json(self.manifest_path, manifest)
        except Exception:
            try:
                key_path.unlink()
            except OSError:
                pass
            raise
        self._manifest = manifest
        self._keys[target] = key
        return {"from": source, "to": target, "state": "migrating"}

    def mark_rotation_verified(self) -> dict[str, str]:
        rotation = self.rotation_state
        if rotation is None or rotation["state"] != "migrating":
            raise RuntimeError("no key rotation is awaiting verification")
        manifest = copy.deepcopy(self._manifest)
        manifest["rotation"]["state"] = "verified"
        _atomic_write_json(self.manifest_path, manifest)
        self._manifest = manifest
        return {**rotation, "state": "verified"}

    def retire_previous_key(self, *, confirm_backups_accounted_for: bool) -> str:
        if confirm_backups_accounted_for is not True:
            raise ValueError(
                "retiring a key requires confirm_backups_accounted_for=true"
            )
        rotation = self.rotation_state
        if rotation is None or rotation["state"] != "verified":
            raise RuntimeError("key rotation must be fully verified before retirement")
        source = rotation["from"]
        manifest = copy.deepcopy(self._manifest)
        keys = manifest["keys"]
        entry = keys.get(source)
        if not isinstance(entry, dict):
            raise KeyUnavailable("previous profile key reference is missing")
        key_path = self.profile_dir / str(entry["ref"])
        _require_owner_file(key_path, "previous profile key")
        del keys[source]
        manifest.pop("rotation", None)
        _atomic_write_json(self.manifest_path, manifest)
        self._manifest = manifest
        self._keys.pop(source, None)
        key_path.unlink()
        return source

    def _create_manifest(self) -> dict[str, Any]:
        keys_dir = _secure_directory(self.profile_dir / "keys")
        key = AESGCM.generate_key(bit_length=256)
        key_id = key_id_for(key)
        key_path = keys_dir / f"{key_id}.key"
        _write_new_key(key_path, key)
        scope_id = f"scope-{os.urandom(16).hex()}"
        manifest: dict[str, Any] = {
            "version": KEYRING_SCHEMA_VERSION,
            "active_key_id": key_id,
            "scope_id": scope_id,
            "scope_binding": _scope_binding(key, self.scope, scope_id),
            "keys": {
                key_id: {
                    "ref": f"keys/{key_id}.key",
                    "status": "active",
                }
            },
        }
        _atomic_write_json(self.manifest_path, manifest)
        return manifest

    def _load_manifest(self) -> dict[str, Any]:
        _require_owner_file(self.manifest_path, "profile key manifest")
        raw = self.manifest_path.read_bytes()
        if not raw or len(raw) > 64 * 1024:
            raise KeyUnavailable("profile key manifest has an invalid size")
        try:
            decoded = strict_json_loads(raw)
        except Exception as exc:
            raise KeyUnavailable("profile key manifest is invalid JSON") from exc
        if not isinstance(decoded, dict):
            raise KeyUnavailable("profile key manifest must be an object")
        allowed = {
            "version",
            "active_key_id",
            "scope_id",
            "scope_binding",
            "keys",
            "rotation",
        }
        if set(decoded) - allowed or set(decoded) < allowed - {"rotation"}:
            raise KeyUnavailable("profile key manifest fields are invalid")
        if decoded["version"] != KEYRING_SCHEMA_VERSION:
            raise KeyUnavailable("profile key manifest version is unsupported")
        _validate_key_id(decoded["active_key_id"])
        _validate_scope_id(decoded["scope_id"])
        binding = decoded["scope_binding"]
        if (
            not isinstance(binding, str)
            or len(binding) != 64
            or any(character not in "0123456789abcdef" for character in binding)
        ):
            raise KeyUnavailable("profile scope binding is invalid")
        keys = decoded["keys"]
        if not isinstance(keys, dict) or not keys or len(keys) > 8:
            raise KeyUnavailable("profile key references are invalid")
        active_count = 0
        for key_id, entry in keys.items():
            _validate_key_id(key_id)
            if not isinstance(entry, dict) or set(entry) != {"ref", "status"}:
                raise KeyUnavailable("profile key reference is invalid")
            reference = entry["ref"]
            status_value = entry["status"]
            if (
                not isinstance(reference, str)
                or _KEY_REF_RE.fullmatch(reference) is None
                or status_value not in {"active", "decrypt-only"}
            ):
                raise KeyUnavailable("profile key reference is invalid")
            if status_value == "active":
                active_count += 1
        if active_count != 1 or keys[decoded["active_key_id"]]["status"] != "active":
            raise KeyUnavailable("profile active key state is invalid")
        return decoded

    def _load_referenced_keys(self) -> None:
        keys = self._manifest["keys"]
        for key_id, entry in keys.items():
            reference = str(entry["ref"])
            key_path = self.profile_dir / reference
            resolved_parent = key_path.parent.resolve()
            if resolved_parent not in {
                self.profile_dir.resolve(),
                (self.profile_dir / "keys").resolve(),
            }:
                raise KeyUnavailable("profile key reference escapes its profile")
            key = _read_key(key_path)
            if not hmac.compare_digest(key_id_for(key), key_id):
                raise KeyUnavailable("profile key does not match its key ID")
            self._keys[key_id] = key

    def _verify_scope_binding(self) -> None:
        expected = _scope_binding(
            self.active_key(),
            self.scope,
            self.scope_id,
        )
        if not hmac.compare_digest(expected, str(self._manifest["scope_binding"])):
            raise PermissionError("authorization scope does not match this profile")


def scoped_aad(
    *,
    object_type: str,
    scope_id: str,
    record_id: str,
    schema_version: int,
    key_id: str,
    ordinal: int | None = None,
    dimension: int | None = None,
) -> bytes:
    if object_type not in {"payload", "retrieval-vector", "lifecycle-anchor"}:
        raise ValueError("encrypted object type is invalid")
    _validate_scope_id(scope_id)
    _validate_record_id(record_id)
    _validate_key_id(key_id)
    if schema_version != SCOPED_VECTOR_SCHEMA_VERSION:
        raise ValueError("encrypted object schema version is unsupported")
    payload: dict[str, object] = {
        "key_id": key_id,
        "object_type": object_type,
        "record_id": record_id,
        "schema_version": schema_version,
        "scope_id": scope_id,
    }
    if ordinal is not None:
        if isinstance(ordinal, bool) or not isinstance(ordinal, int) or ordinal < 0:
            raise ValueError("encrypted object ordinal is invalid")
        payload["ordinal"] = ordinal
    if dimension is not None:
        if (
            isinstance(dimension, bool)
            or not isinstance(dimension, int)
            or not 0 < dimension <= MAX_VECTOR_ELEMENTS
        ):
            raise ValueError("encrypted object dimension is invalid")
        payload["dimension"] = dimension
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


@dataclass(frozen=True)
class ScopedProtectedVector:
    """AES-GCM vector whose security context is carried and authenticated."""

    key_id: str
    scope_id: str
    record_id: str
    nonce: bytes
    ciphertext: bytes
    shape: tuple[int, ...]
    schema_version: int = SCOPED_VECTOR_SCHEMA_VERSION
    algorithm: str = "AES-256-GCM-SCOPED"
    dtype: str = "float64"

    def __post_init__(self) -> None:
        _validate_key_id(self.key_id)
        _validate_scope_id(self.scope_id)
        _validate_record_id(self.record_id)
        if self.schema_version != SCOPED_VECTOR_SCHEMA_VERSION:
            raise ValueError("scoped protected vector schema version is unsupported")
        if self.algorithm != "AES-256-GCM-SCOPED" or self.dtype != "float64":
            raise ValueError("scoped protected vector metadata is invalid")
        if not isinstance(self.nonce, bytes) or len(self.nonce) != AES_GCM_NONCE_BYTES:
            raise ValueError("scoped protected vector nonce is invalid")
        if (
            not isinstance(self.shape, tuple)
            or len(self.shape) != 1
            or isinstance(self.shape[0], bool)
            or not isinstance(self.shape[0], int)
            or not 0 < self.shape[0] <= MAX_VECTOR_ELEMENTS
        ):
            raise ValueError("scoped protected vector shape is invalid")
        expected = self.shape[0] * np.dtype(np.float64).itemsize + AES_GCM_TAG_BYTES
        if not isinstance(self.ciphertext, bytes) or len(self.ciphertext) != expected:
            raise ValueError("scoped protected vector ciphertext size is invalid")

    def associated_data(self) -> bytes:
        return scoped_aad(
            object_type="lifecycle-anchor",
            scope_id=self.scope_id,
            record_id=self.record_id,
            schema_version=self.schema_version,
            key_id=self.key_id,
            dimension=self.shape[0],
        )

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "algorithm": self.algorithm,
                "ciphertext_b64": base64.urlsafe_b64encode(self.ciphertext).decode(
                    "ascii"
                ),
                "dtype": self.dtype,
                "key_id": self.key_id,
                "nonce_b64": base64.urlsafe_b64encode(self.nonce).decode("ascii"),
                "record_id": self.record_id,
                "schema_version": self.schema_version,
                "scope_id": self.scope_id,
                "shape": list(self.shape),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "ScopedProtectedVector":
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > MAX_SCOPED_VECTOR_JSON_BYTES
        ):
            raise ValueError("scoped protected vector JSON has an invalid size")
        try:
            decoded = strict_json_loads(payload)
        except Exception as exc:
            raise ValueError("scoped protected vector JSON is invalid") from exc
        expected = {
            "algorithm",
            "ciphertext_b64",
            "dtype",
            "key_id",
            "nonce_b64",
            "record_id",
            "schema_version",
            "scope_id",
            "shape",
        }
        if not isinstance(decoded, dict) or set(decoded) != expected:
            raise ValueError("scoped protected vector fields are invalid")
        shape = decoded["shape"]
        if (
            not isinstance(shape, list)
            or len(shape) != 1
            or isinstance(shape[0], bool)
            or not isinstance(shape[0], int)
        ):
            raise ValueError("scoped protected vector shape is invalid")
        try:
            nonce = base64.b64decode(
                str(decoded["nonce_b64"]).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
            ciphertext = base64.b64decode(
                str(decoded["ciphertext_b64"]).encode("ascii"),
                altchars=b"-_",
                validate=True,
            )
        except Exception as exc:
            raise ValueError("scoped protected vector encoding is invalid") from exc
        return cls(
            algorithm=str(decoded["algorithm"]),
            ciphertext=ciphertext,
            dtype=str(decoded["dtype"]),
            key_id=str(decoded["key_id"]),
            nonce=nonce,
            record_id=str(decoded["record_id"]),
            schema_version=int(decoded["schema_version"]),
            scope_id=str(decoded["scope_id"]),
            shape=(shape[0],),
        )


class ScopedAesGcmShield:
    """Record-bound AES-GCM shield backed by a multi-key profile keyring."""

    algorithm = "AES-256-GCM-SCOPED"
    production_ready = False
    staging_ready = True

    def __init__(self, keyring: ProfileKeyring) -> None:
        if not isinstance(keyring, ProfileKeyring):
            raise TypeError("ScopedAesGcmShield requires a ProfileKeyring")
        self.keyring = keyring

    def protect(self, _anchor: NDArray[np.float64]) -> ScopedProtectedVector:
        raise RuntimeError("scoped encryption requires a stable record ID")

    def protect_for_record(
        self,
        anchor: NDArray[np.float64],
        record_id: str,
    ) -> ScopedProtectedVector:
        clean_id = _validate_record_id(record_id)
        vector = as_vector(anchor, allow_empty=False, name="anchor vector").astype(
            np.float64,
            copy=False,
        )
        if vector.size > MAX_VECTOR_ELEMENTS:
            raise ValueError("anchor vector exceeds the safety limit")
        key_id = self.keyring.active_key_id
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        protected = ScopedProtectedVector(
            key_id=key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            nonce=nonce,
            ciphertext=b"\0" * (vector.nbytes + AES_GCM_TAG_BYTES),
            shape=(int(vector.size),),
        )
        ciphertext = AESGCM(self.keyring.key(key_id)).encrypt(
            nonce,
            vector.tobytes(order="C"),
            protected.associated_data(),
        )
        return ScopedProtectedVector(
            key_id=key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            nonce=nonce,
            ciphertext=ciphertext,
            shape=(int(vector.size),),
        )

    def reveal(self, protected_anchor: object) -> NDArray[np.float64]:
        protected = self._validate(protected_anchor)
        plaintext = bytearray()
        try:
            plaintext = bytearray(
                AESGCM(self.keyring.key(protected.key_id)).decrypt(
                    protected.nonce,
                    protected.ciphertext,
                    protected.associated_data(),
                )
            )
            expected = protected.shape[0] * np.dtype(np.float64).itemsize
            if len(plaintext) != expected:
                raise ValueError("protected vector plaintext size is invalid")
            vector = np.frombuffer(plaintext, dtype=np.float64).copy()
            if not np.isfinite(vector).all():
                raise ValueError("protected vector contains non-finite values")
            return vector
        except InvalidTag as exc:
            raise ValueError("protected vector authentication failed") from exc
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

    def similarity(
        self,
        intent: NDArray[np.float64],
        protected_anchor: object,
    ) -> float:
        return cosine_similarity(intent, self.reveal(protected_anchor))

    def reencrypt(
        self,
        protected_anchor: ScopedProtectedVector,
        *,
        target_key_id: str,
    ) -> ScopedProtectedVector:
        target = _validate_key_id(target_key_id)
        vector = self.reveal(protected_anchor)
        try:
            nonce = os.urandom(AES_GCM_NONCE_BYTES)
            placeholder = ScopedProtectedVector(
                key_id=target,
                scope_id=protected_anchor.scope_id,
                record_id=protected_anchor.record_id,
                nonce=nonce,
                ciphertext=b"\0" * (vector.nbytes + AES_GCM_TAG_BYTES),
                shape=protected_anchor.shape,
            )
            ciphertext = AESGCM(self.keyring.key(target)).encrypt(
                nonce,
                vector.astype(np.float64, copy=False).tobytes(order="C"),
                placeholder.associated_data(),
            )
            return ScopedProtectedVector(
                key_id=target,
                scope_id=protected_anchor.scope_id,
                record_id=protected_anchor.record_id,
                nonce=nonce,
                ciphertext=ciphertext,
                shape=protected_anchor.shape,
            )
        finally:
            vector.fill(0.0)

    def _validate(self, value: object) -> ScopedProtectedVector:
        if not isinstance(value, ScopedProtectedVector):
            raise TypeError("scoped shield expects a ScopedProtectedVector")
        if value.scope_id != self.keyring.scope_id:
            raise PermissionError("protected vector belongs to another scope")
        return value


def opaque_topic(key: bytes, scope_id: str, topic: str) -> str:
    _validate_scope_id(scope_id)
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(b"echo-veil-topic-v2\0")
    digest.update(scope_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(topic.encode("utf-8"))
    return f"topic-{digest.hexdigest()}"


def validate_finite_timestamp(value: object, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} must be a finite timestamp")
    result = float(value)
    if not math.isfinite(result) or result < 0.0:
        raise ValueError(f"{field} must be a finite timestamp")
    return result
