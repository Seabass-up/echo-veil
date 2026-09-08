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
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, replace
from pathlib import Path
from threading import RLock
from typing import Any

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from numpy.typing import NDArray

from ._json import strict_json_loads
from .key_custody import (
    FILE_CUSTODY_V1,
    OPAQUE_KEY_CUSTODY,
    CustodyClient,
    CustodyDescriptor,
    MacOSKeyCustodyClient,
    executable_cdhash,
    helper_identity,
)
from .record_envelope import (
    KEY_PURPOSE_BACKUP_MANIFEST,
    KEY_PURPOSE_LSH_INDEX,
    KEY_PURPOSE_SEMANTIC_CONTRACT,
    KEY_PURPOSE_VECTOR,
    RECORD_ENVELOPE_KEY_PURPOSES,
    RECORD_ENVELOPE_V2,
    RECORD_ENVELOPE_V3,
    RECORD_ENVELOPE_V3_ALGORITHM,
    RECORD_ENVELOPE_V3_FEATURE,
    SUPPORTED_RECORD_ENVELOPES,
    derive_record_envelope_key,
)
from .vectors import as_vector, cosine_similarity

KEYRING_SCHEMA_VERSION = 1
SCOPED_VECTOR_SCHEMA_VERSION = RECORD_ENVELOPE_V2
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
AES_256_KEY_BYTES = 32
MAX_VECTOR_ELEMENTS = 4_000_000
MAX_SCOPED_VECTOR_JSON_BYTES = 64 * 1024 * 1024
MAX_SCOPED_BLOB_PLAINTEXT_BYTES = 1024
MAX_SCOPED_BLOB_JSON_BYTES = 2048
MAX_SCOPE_CHARS = 256
MAX_PROFILE_FEATURES = 16
SUPPORTED_PROFILE_FEATURES = frozenset(
    {
        "record-integrity-hmac-v1",
        RECORD_ENVELOPE_V3_FEATURE,
        "shielded-four-layer-v1",
    }
)
KEY_ID_PREFIX = "ev-"
_KEY_ID_RE = re.compile(r"ev-[0-9a-f]{16}\Z")
_RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SCOPE_ID_RE = re.compile(r"scope-[0-9a-f]{32}\Z")
_KEY_REF_RE = re.compile(r"(?:agent\.key|keys/ev-[0-9a-f]{16}\.key)\Z")
_CUSTODY_REF_RE = re.compile(r"evkc-[0-9a-f]{32}\Z")
_PROCESS_INSTANCE_RE = re.compile(r"[0-9a-f]{32}\Z")
_CUSTODY_ACTIVATION_SCHEMA = "echo-veil-custody-activation-v1"
_PROCESS_INSTANCE_ID = secrets.token_hex(16)
_POSIX_SQLITE_CREATE_LOCK = RLock()


class KeyUnavailable(RuntimeError):
    """A referenced profile key is missing or cannot be used safely."""


@dataclass(frozen=True)
class _WindowsFileState:
    """Identity and ACL material pinned to one native Windows file handle."""

    identity: tuple[int, ...]
    owner: bytes
    dacl: bytes


@dataclass(frozen=True)
class _PosixFileState:
    """Identity and access material pinned to one POSIX descriptor."""

    identity: tuple[int, int, int]
    uid: int
    mode: int


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


def _scope_binding_message(
    scope: str,
    scope_id: str,
    *,
    features: tuple[str, ...] = (),
    key_epochs: tuple[tuple[str, int], ...] = (),
) -> bytes:
    message = bytearray(b"echo-veil-scope-binding-v1\0")
    message.extend(scope_id.encode("ascii"))
    message.extend(b"\0")
    message.extend(scope.encode("utf-8"))
    for feature in features:
        message.extend(b"\0feature\0")
        message.extend(feature.encode("ascii"))
    for key_id, epoch in key_epochs:
        message.extend(b"\0key-epoch\0")
        message.extend(key_id.encode("ascii"))
        message.extend(b"\0")
        message.extend(str(epoch).encode("ascii"))
    return bytes(message)


def _scope_binding(
    key: bytes,
    scope: str,
    scope_id: str,
    *,
    features: tuple[str, ...] = (),
    key_epochs: tuple[tuple[str, int], ...] = (),
) -> str:
    return hmac.new(
        key,
        _scope_binding_message(
            scope,
            scope_id,
            features=features,
            key_epochs=key_epochs,
        ),
        hashlib.sha256,
    ).hexdigest()


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
        try:
            information = component.lstat()
        except FileNotFoundError:
            continue
        reparse_attribute = int(
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        )
        if stat.S_ISLNK(information.st_mode) or (
            os.name == "nt"
            and bool(
                int(getattr(information, "st_file_attributes", 0)) & reparse_attribute
            )
        ):
            raise ValueError("security-sensitive paths must not contain symbolic links")


def _posix_current_uid() -> int:
    getuid = getattr(os, "getuid", None)
    if os.name == "nt" or not callable(getuid):
        raise OSError("POSIX ownership checks are unavailable")
    return int(getuid())


def _posix_identity(information: os.stat_result) -> tuple[int, int, int]:
    return (
        int(information.st_dev),
        int(information.st_ino),
        int(stat.S_IFMT(information.st_mode)),
    )


def _posix_directory_flags() -> int:
    directory = getattr(os, "O_DIRECTORY", None)
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(directory, int) or not isinstance(nofollow, int):
        raise OSError("POSIX directory pinning flags are unavailable")
    return os.O_RDONLY | directory | nofollow | int(getattr(os, "O_CLOEXEC", 0))


def _posix_validate_directory(
    information: os.stat_result,
    *,
    private_leaf: bool,
) -> None:
    if not stat.S_ISDIR(information.st_mode):
        raise OSError("security-sensitive ancestry is not a directory")
    expected_uid = _posix_current_uid()
    owner = int(information.st_uid)
    mode = stat.S_IMODE(information.st_mode)
    if private_leaf:
        if owner != expected_uid or mode & 0o077:
            raise PermissionError(
                "security-sensitive directory must be current-user owner-only"
            )
        return
    if owner not in {0, expected_uid}:
        raise PermissionError("security-sensitive ancestry has an untrusted owner")
    if mode & 0o022:
        trusted_sticky_root = owner == 0 and bool(information.st_mode & stat.S_ISVTX)
        if not trusted_sticky_root:
            raise PermissionError("security-sensitive ancestry is replaceable")


@contextmanager
def _posix_pinned_directory_chain(
    path: Path,
    *,
    private_leaf: bool = True,
) -> Iterator[int]:
    """Pin a private directory and every trusted namespace edge above it."""

    if os.name == "nt":
        raise OSError("POSIX directory pinning is unavailable")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.is_absolute() or absolute == Path(absolute.anchor):
        raise OSError("private directory boundary is unsupported")
    flags = _posix_directory_flags()
    descriptors: list[int] = []
    edges: list[tuple[int | None, str, _PosixFileState]] = []
    try:
        root = os.open(absolute.anchor, flags)
        descriptors.append(root)
        root_info = os.fstat(root)
        _posix_validate_directory(root_info, private_leaf=False)
        edges.append(
            (
                None,
                absolute.anchor,
                _PosixFileState(
                    identity=_posix_identity(root_info),
                    uid=int(root_info.st_uid),
                    mode=stat.S_IMODE(root_info.st_mode),
                ),
            )
        )
        parent_descriptor = root
        parts = absolute.parts[1:]
        for index, part in enumerate(parts):
            descriptor = os.open(part, flags, dir_fd=parent_descriptor)
            descriptors.append(descriptor)
            information = os.fstat(descriptor)
            _posix_validate_directory(
                information,
                private_leaf=private_leaf and index == len(parts) - 1,
            )
            namespace = os.stat(
                part,
                dir_fd=parent_descriptor,
                follow_symlinks=False,
            )
            if _posix_identity(namespace) != _posix_identity(information):
                raise OSError("security-sensitive directory identity changed")
            edges.append(
                (
                    parent_descriptor,
                    part,
                    _PosixFileState(
                        identity=_posix_identity(information),
                        uid=int(information.st_uid),
                        mode=stat.S_IMODE(information.st_mode),
                    ),
                )
            )
            parent_descriptor = descriptor
        yield parent_descriptor
        for edge_parent_descriptor, name, expected in edges:
            information = (
                os.lstat(name)
                if edge_parent_descriptor is None
                else os.stat(
                    name,
                    dir_fd=edge_parent_descriptor,
                    follow_symlinks=False,
                )
            )
            if (
                _posix_identity(information) != expected.identity
                or int(information.st_uid) != expected.uid
                or stat.S_IMODE(information.st_mode) != expected.mode
            ):
                raise OSError("security-sensitive directory identity changed")
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def _posix_verify_private_file_descriptor(
    descriptor: int,
    parent_descriptor: int,
    name: str,
    *,
    label: str,
) -> _PosixFileState:
    descriptor_info = os.fstat(descriptor)
    namespace_info = os.stat(
        name,
        dir_fd=parent_descriptor,
        follow_symlinks=False,
    )
    expected_uid = _posix_current_uid()
    if (
        not stat.S_ISREG(descriptor_info.st_mode)
        or not stat.S_ISREG(namespace_info.st_mode)
        or int(descriptor_info.st_uid) != expected_uid
        or int(namespace_info.st_uid) != expected_uid
        or int(descriptor_info.st_nlink) != 1
        or int(namespace_info.st_nlink) != 1
        or stat.S_IMODE(descriptor_info.st_mode) & 0o077
        or stat.S_IMODE(namespace_info.st_mode) & 0o077
        or _posix_identity(descriptor_info) != _posix_identity(namespace_info)
    ):
        raise PermissionError(f"{label} POSIX ownership or identity is unsafe")
    return _PosixFileState(
        identity=_posix_identity(descriptor_info),
        uid=int(descriptor_info.st_uid),
        mode=stat.S_IMODE(descriptor_info.st_mode),
    )


@contextmanager
def _posix_open_private_file(
    path: Path,
    flags: int,
    *,
    label: str,
    mode: int = 0o600,
) -> Iterator[int]:
    """Open one private file relative to a pinned owner-only parent."""

    if os.name == "nt":
        raise OSError("POSIX private file open is unavailable")
    absolute = Path(os.path.abspath(os.fspath(path)))
    safe_flags = flags | int(getattr(os, "O_CLOEXEC", 0))
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(nofollow, int):
        raise OSError("POSIX no-follow file opens are unavailable")
    safe_flags |= nofollow
    with _posix_pinned_directory_chain(absolute.parent) as parent_descriptor:
        for attempt in range(3):
            try:
                descriptor = os.open(
                    absolute.name,
                    safe_flags,
                    mode,
                    dir_fd=parent_descriptor,
                )
                break
            except FileNotFoundError as exc:
                if not safe_flags & os.O_CREAT:
                    raise
                pinned = os.fstat(parent_descriptor)
                try:
                    namespace = os.stat(
                        absolute.parent,
                        follow_symlinks=False,
                    )
                except FileNotFoundError:
                    namespace = None
                if (
                    namespace is None
                    or int(pinned.st_nlink) == 0
                    or _posix_identity(namespace) != _posix_identity(pinned)
                    or attempt == 2
                ):
                    raise OSError(
                        "private file parent identity changed during open"
                    ) from exc
        try:
            expected = _posix_verify_private_file_descriptor(
                descriptor,
                parent_descriptor,
                absolute.name,
                label=label,
            )
            yield descriptor
            current = _posix_verify_private_file_descriptor(
                descriptor,
                parent_descriptor,
                absolute.name,
                label=label,
            )
            if current != expected:
                raise OSError(f"{label} POSIX identity changed while open")
        finally:
            os.close(descriptor)


def _posix_stat_private_file(path: Path, *, label: str) -> _PosixFileState:
    """Observe private metadata without closing a descriptor on a live SQLite inode."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    with _posix_pinned_directory_chain(absolute.parent) as parent_descriptor:
        observed: _PosixFileState | None = None
        for _ in range(2):
            information = os.stat(
                absolute.name, dir_fd=parent_descriptor, follow_symlinks=False
            )
            if (
                not stat.S_ISREG(information.st_mode)
                or int(information.st_uid) != _posix_current_uid()
                or int(information.st_nlink) != 1
                or stat.S_IMODE(information.st_mode) & 0o077
            ):
                raise PermissionError(f"{label} POSIX ownership or identity is unsafe")
            current = _PosixFileState(
                identity=_posix_identity(information),
                uid=int(information.st_uid),
                mode=stat.S_IMODE(information.st_mode),
            )
            if observed is not None and current != observed:
                raise OSError(f"{label} POSIX identity changed during inspection")
            observed = current
    assert observed is not None
    return observed


def _posix_prepare_private_sqlite_file(path: Path, *, label: str) -> _PosixFileState:
    """Create exclusively or inspect an existing database without opening it."""

    # Even a read-only open/close cancels the process's POSIX SQLite locks.
    # Serialize creation so another local initializer cannot open a new database
    # before its creating descriptor has closed.
    with _POSIX_SQLITE_CREATE_LOCK:
        try:
            with _posix_open_private_file(
                path, os.O_RDWR | os.O_CREAT | os.O_EXCL, label=label
            ):
                pass
        except FileExistsError:
            pass
        return _posix_stat_private_file(path, label=label)


def _secure_directory(path: Path) -> Path:
    _reject_symlink_components(path)
    if os.name == "nt":
        return _windows_ensure_private_directory(path)
    path = Path(os.path.abspath(os.fspath(path)))
    existing_ancestor = path
    while not existing_ancestor.exists():
        if existing_ancestor == existing_ancestor.parent:
            raise OSError("profile key directory has no trusted ancestor")
        existing_ancestor = existing_ancestor.parent
    missing_parts = path.relative_to(existing_ancestor).parts
    with _posix_pinned_directory_chain(
        existing_ancestor,
        private_leaf=False,
    ) as existing_descriptor:
        parent_descriptor = existing_descriptor
        created_descriptors: list[int] = []
        created_edges: list[tuple[int, str, _PosixFileState]] = []
        try:
            for part in missing_parts:
                try:
                    os.mkdir(part, mode=0o700, dir_fd=parent_descriptor)
                    os.fsync(parent_descriptor)
                except FileExistsError:
                    # A concurrent creator must still satisfy the same private
                    # ownership and identity contract before it can be used.
                    pass
                descriptor = os.open(
                    part,
                    _posix_directory_flags(),
                    dir_fd=parent_descriptor,
                )
                created_descriptors.append(descriptor)
                information = os.fstat(descriptor)
                _posix_validate_directory(information, private_leaf=True)
                namespace = os.stat(
                    part,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
                if _posix_identity(namespace) != _posix_identity(information):
                    raise OSError("profile key directory identity changed")
                created_edges.append(
                    (
                        parent_descriptor,
                        part,
                        _PosixFileState(
                            identity=_posix_identity(information),
                            uid=int(information.st_uid),
                            mode=stat.S_IMODE(information.st_mode),
                        ),
                    )
                )
                parent_descriptor = descriptor
            for edge_parent, name, expected in created_edges:
                current = os.stat(
                    name,
                    dir_fd=edge_parent,
                    follow_symlinks=False,
                )
                if (
                    _posix_identity(current) != expected.identity
                    or int(current.st_uid) != expected.uid
                    or stat.S_IMODE(current.st_mode) != expected.mode
                ):
                    raise OSError("profile key directory identity changed")
        finally:
            for descriptor in reversed(created_descriptors):
                os.close(descriptor)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("profile key directory must be a regular directory")
    with _posix_pinned_directory_chain(path):
        pass
    return path


def _require_owner_file(path: Path, label: str) -> None:
    try:
        _reject_symlink_components(path)
    except ValueError as exc:
        raise KeyUnavailable(f"{label} path is unsafe") from exc
    if path.is_symlink() or not path.is_file():
        raise KeyUnavailable(f"{label} is missing")
    if os.name == "nt":
        try:
            with _windows_pinned_directory_chain(path.parent):
                descriptor = _windows_open_private_file(path, writable=False)
                try:
                    _windows_verify_descriptor(
                        descriptor,
                        path,
                        expected_payload=None,
                        expected_security=_windows_expected_private_security(),
                    )
                finally:
                    os.close(descriptor)
        except OSError as exc:
            raise KeyUnavailable(f"{label} Windows DACL or identity is unsafe") from exc
    else:
        try:
            with _posix_open_private_file(path, os.O_RDONLY, label=label):
                pass
        except OSError as exc:
            raise KeyUnavailable(
                f"{label} POSIX ownership or identity is unsafe"
            ) from exc


def _binary_noninheritable_read_flags() -> int:
    """Return raw-file read flags without Windows CRT byte translation."""

    flags = os.O_RDONLY
    if os.name == "nt":
        binary = getattr(os, "O_BINARY", None)
        noninheritable = getattr(os, "O_NOINHERIT", None)
        if (
            not isinstance(binary, int)
            or binary == 0
            or not isinstance(noninheritable, int)
            or noninheritable == 0
        ):
            raise OSError("Windows binary non-inheritable open flags are unavailable")
        flags |= binary | noninheritable
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _read_key(path: Path) -> bytes:
    raw = _read_private_file_bytes(
        path,
        label="profile key",
        maximum=AES_256_KEY_BYTES,
    )
    if len(raw) != AES_256_KEY_BYTES:
        raise KeyUnavailable("profile key has an invalid length")
    return raw


def _read_private_file_bytes(path: Path, *, label: str, maximum: int) -> bytes:
    """Read a bounded private file through one identity-checked descriptor."""

    if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
        raise ValueError("private file read bound must be a positive integer")
    try:
        _reject_symlink_components(path)
        if os.name == "nt":
            target = path.absolute()
            with _windows_pinned_directory_chain(target.parent):
                descriptor = _windows_open_private_file(target, writable=False)
                try:
                    _windows_verify_descriptor(
                        descriptor,
                        target,
                        expected_payload=None,
                        expected_security=_windows_expected_private_security(),
                    )
                    return _read_bounded(descriptor, maximum)
                finally:
                    os.close(descriptor)
        with _posix_open_private_file(
            path,
            _binary_noninheritable_read_flags(),
            label=label,
        ) as descriptor:
            return _read_bounded(descriptor, maximum)
    except (OSError, ValueError) as exc:
        raise KeyUnavailable(
            f"{label} permissions, ownership, or identity are unsafe"
        ) from exc


def _read_bounded(descriptor: int, maximum: int) -> bytes:
    chunks: list[bytes] = []
    remaining = maximum + 1
    while remaining > 0:
        chunk = os.read(descriptor, min(remaining, 64 * 1024))
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _write_new_key(path: Path, key: bytes) -> None:
    if len(key) != AES_256_KEY_BYTES:
        raise ValueError("profile key must contain exactly 32 bytes")
    _reject_symlink_components(path)
    _secure_directory(path.parent)
    if os.name == "nt":
        with _windows_pinned_directory_chain(path.parent):
            descriptor, created_state = _windows_create_private_staging(path)
            try:
                _write_all(descriptor, key)
                os.fsync(descriptor)
                _windows_verify_descriptor(
                    descriptor,
                    path,
                    expected_payload=key,
                    expected_state=created_state,
                )
            finally:
                os.close(descriptor)
        return
    target = path.absolute()
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | int(getattr(os, "O_CLOEXEC", 0))
        | int(getattr(os, "O_NOFOLLOW"))
    )
    with _posix_pinned_directory_chain(target.parent) as parent_descriptor:
        descriptor = os.open(
            target.name,
            flags,
            0o600,
            dir_fd=parent_descriptor,
        )
        published = True
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            expected = _posix_verify_private_file_descriptor(
                descriptor,
                parent_descriptor,
                target.name,
                label="profile key",
            )
            _write_all(descriptor, key)
            os.fsync(descriptor)
            current = _posix_verify_private_file_descriptor(
                descriptor,
                parent_descriptor,
                target.name,
                label="profile key",
            )
            if current != expected:
                raise OSError("profile key identity changed while writing")
        except Exception:
            published = False
            try:
                os.unlink(target.name, dir_fd=parent_descriptor)
            except FileNotFoundError:
                pass
            raise
        finally:
            os.close(descriptor)
        if not published:
            raise OSError("profile key publication failed")
        os.fsync(parent_descriptor)


def _atomic_write_json(path: Path, payload: dict[str, Any]) -> None:
    _reject_symlink_components(path)
    encoded = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    if os.name == "nt":
        _atomic_write_json_windows(path, encoded)
        return
    target = Path(os.path.abspath(os.fspath(path)))
    with _posix_pinned_directory_chain(target.parent) as parent_descriptor:
        try:
            existing_descriptor = os.open(
                target.name,
                os.O_RDONLY
                | int(getattr(os, "O_CLOEXEC", 0))
                | int(getattr(os, "O_NOFOLLOW")),
                dir_fd=parent_descriptor,
            )
        except FileNotFoundError:
            existing_descriptor = -1
        if existing_descriptor >= 0:
            try:
                _posix_verify_private_file_descriptor(
                    existing_descriptor,
                    parent_descriptor,
                    target.name,
                    label="profile key manifest",
                )
            finally:
                os.close(existing_descriptor)

        descriptor = -1
        temporary_name: str | None = None
        try:
            for _attempt in range(128):
                candidate = f".{target.name}.{secrets.token_hex(16)}.tmp"
                try:
                    descriptor = os.open(
                        candidate,
                        os.O_RDWR
                        | os.O_CREAT
                        | os.O_EXCL
                        | int(getattr(os, "O_CLOEXEC", 0))
                        | int(getattr(os, "O_NOFOLLOW")),
                        0o600,
                        dir_fd=parent_descriptor,
                    )
                except FileExistsError:
                    continue
                temporary_name = candidate
                break
            else:
                raise OSError("profile manifest staging name is unavailable")

            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            staged = _posix_verify_private_file_descriptor(
                descriptor,
                parent_descriptor,
                temporary_name,
                label="profile manifest staging file",
            )
            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            if (
                _posix_verify_private_file_descriptor(
                    descriptor,
                    parent_descriptor,
                    temporary_name,
                    label="profile manifest staging file",
                )
                != staged
            ):
                raise OSError("profile manifest staging identity changed")
            os.replace(
                temporary_name,
                target.name,
                src_dir_fd=parent_descriptor,
                dst_dir_fd=parent_descriptor,
            )
            temporary_name = None
            published_descriptor = os.open(
                target.name,
                os.O_RDONLY
                | int(getattr(os, "O_CLOEXEC", 0))
                | int(getattr(os, "O_NOFOLLOW")),
                dir_fd=parent_descriptor,
            )
            try:
                published = _posix_verify_private_file_descriptor(
                    published_descriptor,
                    parent_descriptor,
                    target.name,
                    label="profile key manifest",
                )
                if published.identity != staged.identity:
                    raise OSError("profile manifest publication identity changed")
                if _read_bounded(published_descriptor, len(encoded)) != encoded:
                    raise OSError("profile manifest publication bytes changed")
            finally:
                os.close(published_descriptor)
            os.fsync(parent_descriptor)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary_name is not None:
                try:
                    os.unlink(temporary_name, dir_fd=parent_descriptor)
                except FileNotFoundError:
                    pass


def _unlink_private_file(path: Path, *, label: str) -> None:
    """Remove one identity-checked private file without path re-resolution."""

    target = path.absolute()
    if os.name == "nt":
        _require_owner_file(target, label)
        with _windows_pinned_directory_chain(target.parent):
            target.unlink()
        return
    with _posix_pinned_directory_chain(target.parent) as parent_descriptor:
        descriptor = os.open(
            target.name,
            os.O_RDONLY
            | int(getattr(os, "O_CLOEXEC", 0))
            | int(getattr(os, "O_NOFOLLOW")),
            dir_fd=parent_descriptor,
        )
        try:
            _posix_verify_private_file_descriptor(
                descriptor,
                parent_descriptor,
                target.name,
                label=label,
            )
            os.unlink(target.name, dir_fd=parent_descriptor)
            try:
                os.stat(
                    target.name,
                    dir_fd=parent_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise OSError(f"{label} name remained after unlink")
        finally:
            os.close(descriptor)
        os.fsync(parent_descriptor)


def _atomic_write_json_windows(path: Path, encoded: bytes) -> None:
    """Publish JSON through an ACL-private, write-through Windows rename."""

    target = Path(os.path.abspath(os.fspath(path)))
    _reject_symlink_components(target)
    with _windows_pinned_directory_chain(target.parent):
        descriptor = -1
        temporary: Path | None = None
        try:
            for _attempt in range(128):
                candidate = target.with_name(
                    f".{target.name}.{secrets.token_hex(16)}.tmp"
                )
                try:
                    descriptor, created_state = _windows_create_private_staging(
                        candidate
                    )
                except FileExistsError:
                    continue
                temporary = candidate
                break
            else:
                raise OSError("profile manifest staging name is unavailable")

            _write_all(descriptor, encoded)
            os.fsync(descriptor)
            staged_state = _windows_verify_descriptor(
                descriptor,
                temporary,
                expected_payload=encoded,
                expected_state=created_state,
            )
            os.close(descriptor)
            descriptor = -1

            _windows_move_file_replace_write_through(temporary, target)
            temporary = None
            _windows_verify_publication(
                target,
                expected_payload=encoded,
                expected_state=staged_state,
            )
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            if temporary is not None:
                try:
                    temporary.unlink()
                except FileNotFoundError:
                    pass


def _windows_create_private_staging(path: Path) -> tuple[int, _WindowsFileState]:
    """Create a file whose private DACL exists before its name becomes visible."""

    if os.name != "nt" or not path.is_absolute():
        raise OSError("atomic Windows private-file creation is unavailable")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("security_descriptor", ctypes.c_void_p),
            ("inherit_handle", wintypes.BOOL),
        ]

    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(_SecurityAttributes),
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE

    current_sid = _windows_current_user_sid_string()
    security_descriptor = ctypes.c_void_p()
    sddl = f"O:{current_sid}D:P(A;;FA;;;SY)(A;;FA;;;{current_sid})"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,  # SDDL_REVISION_1
        ctypes.byref(security_descriptor),
        None,
    ):
        raise win_error(get_last_error())

    handle: int | None = None
    descriptor = -1
    created_by_us = False
    try:
        expected_security = _windows_security_descriptor_fingerprint(
            security_descriptor
        )
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes),
            security_descriptor,
            False,
        )
        created = create_file(
            os.fspath(path),
            0x80000000 | 0x40000000 | 0x00020000,
            # GENERIC_READ | GENERIC_WRITE | READ_CONTROL
            0,
            ctypes.byref(attributes),
            1,  # CREATE_NEW
            0x00000080 | 0x00200000,
            # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
            None,
        )
        invalid_handle = ctypes.c_void_p(-1).value
        if created in {None, invalid_handle}:
            error = int(get_last_error())
            if error in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
                raise FileExistsError(
                    error,
                    "private staging path already exists",
                    os.fspath(path),
                )
            raise win_error(error)
        created_by_us = True
        handle = int(created)
        try:
            descriptor = int(
                getattr(msvcrt, "open_osfhandle")(
                    handle,
                    os.O_RDWR
                    | int(getattr(os, "O_BINARY", 0))
                    | int(getattr(os, "O_NOINHERIT", 0)),
                )
            )
        except Exception:
            kernel32.CloseHandle(wintypes.HANDLE(handle))
            handle = None
            raise
        handle = None  # The CRT descriptor now owns the native handle.
        state = _windows_verify_descriptor(
            descriptor,
            path,
            expected_payload=b"",
            expected_security=expected_security,
        )
        return descriptor, state
    except Exception:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except (OSError, KeyUnavailable):
                pass
        elif handle is not None:
            kernel32.CloseHandle(wintypes.HANDLE(handle))
        if created_by_us:
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        raise
    finally:
        kernel32.LocalFree(security_descriptor)


def _windows_current_user_sid_string() -> str:
    """Return the current process user's SID without leaking native handles."""

    if os.name != "nt":
        raise OSError("Windows identity APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    kernel32.GetCurrentProcess.argtypes = ()
    kernel32.GetCurrentProcess.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.OpenProcessToken.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.HANDLE),
    )
    advapi32.OpenProcessToken.restype = wintypes.BOOL
    advapi32.GetTokenInformation.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetTokenInformation.restype = wintypes.BOOL
    advapi32.ConvertSidToStringSidW.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.ConvertSidToStringSidW.restype = wintypes.BOOL

    class _SidAndAttributes(ctypes.Structure):
        _fields_ = [("sid", ctypes.c_void_p), ("attributes", wintypes.DWORD)]

    class _TokenUser(ctypes.Structure):
        _fields_ = [("user", _SidAndAttributes)]

    token = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(
        kernel32.GetCurrentProcess(),
        0x0008,  # TOKEN_QUERY
        ctypes.byref(token),
    ):
        raise win_error(get_last_error())
    try:
        required = wintypes.DWORD()
        advapi32.GetTokenInformation(
            token,
            1,  # TokenUser
            None,
            0,
            ctypes.byref(required),
        )
        if required.value <= 0:
            raise win_error(get_last_error())
        token_buffer = ctypes.create_string_buffer(required.value)
        if not advapi32.GetTokenInformation(
            token,
            1,
            token_buffer,
            required,
            ctypes.byref(required),
        ):
            raise win_error(get_last_error())
        current_sid = ctypes.cast(
            token_buffer, ctypes.POINTER(_TokenUser)
        ).contents.user.sid
        sid_text = ctypes.c_void_p()
        if not current_sid or not advapi32.ConvertSidToStringSidW(
            current_sid, ctypes.byref(sid_text)
        ):
            raise win_error(get_last_error())
        try:
            return ctypes.wstring_at(sid_text)
        finally:
            kernel32.LocalFree(sid_text)
    finally:
        kernel32.CloseHandle(token)


def _windows_security_descriptor_fingerprint(
    security_descriptor: Any,
    *,
    require_protected: bool = True,
) -> tuple[bytes, bytes]:
    """Return exact owner SID and protected DACL bytes from a descriptor."""

    if os.name != "nt":
        raise OSError("Windows security APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    advapi32.GetSecurityDescriptorOwner.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi32.GetSecurityDescriptorOwner.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.GetSecurityDescriptorControl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.WORD),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.GetSecurityDescriptorControl.restype = wintypes.BOOL
    advapi32.GetLengthSid.argtypes = (ctypes.c_void_p,)
    advapi32.GetLengthSid.restype = wintypes.DWORD

    class _Acl(ctypes.Structure):
        _fields_ = [
            ("revision", ctypes.c_ubyte),
            ("reserved", ctypes.c_ubyte),
            ("size", wintypes.WORD),
            ("ace_count", wintypes.WORD),
            ("reserved2", wintypes.WORD),
        ]

    pointer = ctypes.cast(security_descriptor, ctypes.c_void_p)
    owner = ctypes.c_void_p()
    owner_defaulted = wintypes.BOOL()
    dacl = ctypes.c_void_p()
    dacl_present = wintypes.BOOL()
    dacl_defaulted = wintypes.BOOL()
    control = wintypes.WORD()
    revision = wintypes.DWORD()
    if not advapi32.GetSecurityDescriptorOwner(
        pointer, ctypes.byref(owner), ctypes.byref(owner_defaulted)
    ):
        raise win_error(get_last_error())
    if not advapi32.GetSecurityDescriptorDacl(
        pointer,
        ctypes.byref(dacl_present),
        ctypes.byref(dacl),
        ctypes.byref(dacl_defaulted),
    ):
        raise win_error(get_last_error())
    if not advapi32.GetSecurityDescriptorControl(
        pointer, ctypes.byref(control), ctypes.byref(revision)
    ):
        raise win_error(get_last_error())
    if (
        not owner.value
        or not dacl_present.value
        or not dacl.value
        or (
            require_protected and not int(control.value) & 0x1000  # SE_DACL_PROTECTED
        )
    ):
        raise OSError("private Windows security descriptor is incomplete")
    owner_size = int(advapi32.GetLengthSid(owner))
    dacl_size = int(ctypes.cast(dacl, ctypes.POINTER(_Acl)).contents.size)
    if owner_size <= 0 or dacl_size < ctypes.sizeof(_Acl) or dacl_size > 65_535:
        raise OSError("private Windows security descriptor is invalid")
    return (
        ctypes.string_at(owner, owner_size),
        ctypes.string_at(dacl, dacl_size),
    )


def _windows_descriptor_security(
    descriptor: int,
    *,
    require_protected: bool = True,
) -> tuple[bytes, bytes]:
    """Read owner and DACL through the exact open file handle."""

    if os.name != "nt":
        raise OSError("Windows security APIs are unavailable")
    import msvcrt

    return _windows_handle_security(
        int(getattr(msvcrt, "get_osfhandle")(descriptor)),
        require_protected=require_protected,
    )


def _windows_handle_security(
    handle: int,
    *,
    require_protected: bool = True,
) -> tuple[bytes, bytes]:
    """Read owner and DACL through one exact native Windows handle."""

    if os.name != "nt":
        raise OSError("Windows security APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    win_error = getattr(ctypes, "WinError")
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.GetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(ctypes.c_void_p),
    )
    advapi32.GetSecurityInfo.restype = wintypes.DWORD

    security_descriptor = ctypes.c_void_p()
    result = advapi32.GetSecurityInfo(
        wintypes.HANDLE(handle),
        1,  # SE_FILE_OBJECT
        0x00000001 | 0x00000004,  # OWNER | DACL
        None,
        None,
        None,
        None,
        ctypes.byref(security_descriptor),
    )
    if result != 0:
        raise win_error(result)
    if not security_descriptor.value:
        raise OSError("Windows file security descriptor is unavailable")
    try:
        return _windows_security_descriptor_fingerprint(
            security_descriptor,
            require_protected=require_protected,
        )
    finally:
        kernel32.LocalFree(security_descriptor)


def _windows_expected_private_security(
    *, directory: bool = False
) -> tuple[bytes, bytes]:
    """Build the canonical current-user/System protected security descriptor."""

    if os.name != "nt":
        raise OSError("Windows security APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    current_sid = _windows_current_user_sid_string()
    inheritance = "OICI" if directory else ""
    security_descriptor = ctypes.c_void_p()
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        f"O:{current_sid}D:P(A;{inheritance};FA;;;SY)"
        f"(A;{inheritance};FA;;;{current_sid})",
        1,
        ctypes.byref(security_descriptor),
        None,
    ):
        raise win_error(get_last_error())
    try:
        return _windows_security_descriptor_fingerprint(security_descriptor)
    finally:
        kernel32.LocalFree(security_descriptor)


def _windows_file_identity(information: os.stat_result) -> tuple[int, ...]:
    return (
        int(information.st_dev),
        int(information.st_ino),
        int(stat.S_IFMT(information.st_mode)),
        int(information.st_nlink),
        int(getattr(information, "st_file_attributes", 0)),
    )


def _windows_directory_identity(information: os.stat_result) -> tuple[int, ...]:
    return (
        int(information.st_dev),
        int(information.st_ino),
        int(stat.S_IFMT(information.st_mode)),
        int(getattr(information, "st_file_attributes", 0)),
    )


def _windows_handle_namespace_dacl_is_safe(
    handle: int,
    *,
    reject_untrusted_access: bool = False,
) -> bool:
    """Reject an untrusted principal able to replace a pinned ancestry edge."""

    if os.name != "nt":
        return False
    try:
        import ctypes
        from ctypes import wintypes

        advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
        kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
        kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
        kernel32.LocalFree.restype = ctypes.c_void_p
        advapi32.GetSecurityInfo.argtypes = (
            wintypes.HANDLE,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.GetSecurityInfo.restype = wintypes.DWORD
        advapi32.ConvertStringSidToSidW.argtypes = (
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.ConvertStringSidToSidW.restype = wintypes.BOOL
        advapi32.EqualSid.argtypes = (ctypes.c_void_p, ctypes.c_void_p)
        advapi32.EqualSid.restype = wintypes.BOOL
        advapi32.IsValidSid.argtypes = (ctypes.c_void_p,)
        advapi32.IsValidSid.restype = wintypes.BOOL
        advapi32.GetLengthSid.argtypes = (ctypes.c_void_p,)
        advapi32.GetLengthSid.restype = wintypes.DWORD
        advapi32.GetAclInformation.argtypes = (
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_int,
        )
        advapi32.GetAclInformation.restype = wintypes.BOOL
        advapi32.GetAce.argtypes = (
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(ctypes.c_void_p),
        )
        advapi32.GetAce.restype = wintypes.BOOL

        class _AclSizeInformation(ctypes.Structure):
            _fields_ = [
                ("ace_count", wintypes.DWORD),
                ("bytes_in_use", wintypes.DWORD),
                ("bytes_free", wintypes.DWORD),
            ]

        class _AceHeader(ctypes.Structure):
            _fields_ = [
                ("ace_type", ctypes.c_ubyte),
                ("ace_flags", ctypes.c_ubyte),
                ("ace_size", wintypes.WORD),
            ]

        owner = ctypes.c_void_p()
        dacl = ctypes.c_void_p()
        security_descriptor = ctypes.c_void_p()
        result = advapi32.GetSecurityInfo(
            wintypes.HANDLE(handle),
            1,  # SE_FILE_OBJECT
            0x00000001 | 0x00000004,  # OWNER | DACL
            ctypes.byref(owner),
            None,
            ctypes.byref(dacl),
            None,
            ctypes.byref(security_descriptor),
        )
        if (
            result != 0
            or not owner.value
            or not dacl.value
            or not security_descriptor.value
        ):
            if security_descriptor.value:
                kernel32.LocalFree(security_descriptor)
            return False

        converted_sids: list[ctypes.c_void_p] = []
        try:
            trusted_sid_texts = (
                _windows_current_user_sid_string(),
                "S-1-5-18",  # LocalSystem
                "S-1-5-32-544",  # Builtin Administrators
                "S-1-3-0",  # Creator Owner (inheritance-only)
                "S-1-3-4",  # Owner Rights
                # Windows Modules Installer / TrustedInstaller.
                "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
            )
            trusted_sids: list[ctypes.c_void_p] = []
            for sid_text in trusted_sid_texts:
                sid = ctypes.c_void_p()
                if not advapi32.ConvertStringSidToSidW(sid_text, ctypes.byref(sid)):
                    return False
                converted_sids.append(sid)
                trusted_sids.append(sid)
            if not any(
                advapi32.EqualSid(owner, trusted_sids[index]) for index in (0, 1, 2, 5)
            ):
                return False

            acl_information = _AclSizeInformation()
            if not advapi32.GetAclInformation(
                dacl,
                ctypes.byref(acl_information),
                ctypes.sizeof(acl_information),
                2,  # AclSizeInformation
            ):
                return False
            unsafe_rights = (
                0x00000010  # FILE_WRITE_EA
                | 0x00000040  # FILE_DELETE_CHILD
                | 0x00000100  # FILE_WRITE_ATTRIBUTES
                | 0x00010000  # DELETE
                | 0x00040000  # WRITE_DAC
                | 0x00080000  # WRITE_OWNER
                | 0x10000000  # GENERIC_ALL
                | 0x40000000  # GENERIC_WRITE
            )
            if reject_untrusted_access:
                unsafe_rights |= (
                    0x00000001  # FILE_READ_DATA / FILE_LIST_DIRECTORY
                    | 0x00000002  # FILE_WRITE_DATA / FILE_ADD_FILE
                    | 0x00000004  # FILE_APPEND_DATA / FILE_ADD_SUBDIRECTORY
                    | 0x00000008  # FILE_READ_EA
                    | 0x00000020  # FILE_EXECUTE / FILE_TRAVERSE
                    | 0x00000080  # FILE_READ_ATTRIBUTES
                    | 0x00020000  # READ_CONTROL
                    | 0x20000000  # GENERIC_EXECUTE
                    | 0x80000000  # GENERIC_READ
                )
            allow_ace_types = {0, 4, 5, 9, 11}
            simple_allow_ace_types = {0, 9}
            for index in range(int(acl_information.ace_count)):
                ace_pointer = ctypes.c_void_p()
                if (
                    not advapi32.GetAce(dacl, index, ctypes.byref(ace_pointer))
                    or not ace_pointer.value
                ):
                    return False
                header = ctypes.cast(ace_pointer, ctypes.POINTER(_AceHeader)).contents
                ace_size = int(header.ace_size)
                if ace_size < 8:
                    return False
                if int(header.ace_flags) & 0x08:  # INHERIT_ONLY_ACE
                    continue
                if int(header.ace_type) not in allow_ace_types:
                    continue
                mask = int(ctypes.c_uint32.from_address(ace_pointer.value + 4).value)
                if not mask & unsafe_rights:
                    continue
                if int(header.ace_type) not in simple_allow_ace_types or ace_size < 12:
                    return False
                sid = ctypes.c_void_p(ace_pointer.value + 8)
                if not advapi32.IsValidSid(sid):
                    return False
                sid_length = int(advapi32.GetLengthSid(sid))
                if sid_length <= 0 or 8 + sid_length > ace_size:
                    return False
                if not any(advapi32.EqualSid(sid, trusted) for trusted in trusted_sids):
                    return False
            return True
        finally:
            for sid in converted_sids:
                kernel32.LocalFree(sid)
            kernel32.LocalFree(security_descriptor)
    except Exception:
        return False


def _windows_descriptor_private_dacl_is_safe(descriptor: int) -> bool:
    """Require that one open file grants no untrusted access rights."""

    if os.name != "nt":
        return False
    import msvcrt

    return _windows_handle_namespace_dacl_is_safe(
        int(getattr(msvcrt, "get_osfhandle")(descriptor)),
        reject_untrusted_access=True,
    )


def _windows_verify_private_sqlite_sidecars(database: Path) -> None:
    """Fail before SQLite opens any stale sidecar with an unsafe DACL."""

    if os.name != "nt":
        return
    with _windows_pinned_directory_chain(database.parent):
        for suffix in ("-wal", "-shm", "-journal"):
            path = Path(f"{database}{suffix}")
            try:
                path.lstat()
            except FileNotFoundError:
                continue
            descriptor = _windows_open_private_file(
                path,
                writable=False,
                share_write=True,
            )
            try:
                _windows_verify_descriptor(
                    descriptor,
                    path,
                    expected_payload=None,
                    require_protected_security=False,
                )
                if not _windows_descriptor_private_dacl_is_safe(descriptor):
                    raise OSError("Windows SQLite sidecar DACL is unsafe")
            finally:
                os.close(descriptor)


def _windows_native_handle_final_path(handle: int) -> Path:
    """Return the normalized DOS path bound to one native Windows handle."""

    if os.name != "nt":
        raise OSError("Windows path APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_final_path = kernel32.GetFinalPathNameByHandleW
    get_final_path.argtypes = (
        wintypes.HANDLE,
        wintypes.LPWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
    )
    get_final_path.restype = wintypes.DWORD
    native_handle = wintypes.HANDLE(handle)
    size = int(get_final_path(native_handle, None, 0, 0))
    if size <= 0 or size > 32_768:
        raise OSError("Windows handle path is unavailable")
    buffer = ctypes.create_unicode_buffer(size + 1)
    written = int(get_final_path(native_handle, buffer, len(buffer), 0))
    if written <= 0 or written >= len(buffer):
        raise OSError("Windows handle path is unavailable")
    value = buffer.value
    if value.startswith("\\\\?\\UNC\\"):
        value = "\\\\" + value[8:]
    elif value.startswith("\\\\?\\"):
        value = value[4:]
    return Path(value)


def _recheck_windows_directory_chain(
    captured: tuple[tuple[Path, tuple[int, ...]], ...],
) -> None:
    reparse_attribute = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))
    for path, identity in captured:
        information = path.lstat()
        if (
            stat.S_ISLNK(information.st_mode)
            or bool(
                int(getattr(information, "st_file_attributes", 0)) & reparse_attribute
            )
            or not stat.S_ISDIR(information.st_mode)
            or _windows_directory_identity(information) != identity
        ):
            raise OSError("Windows profile directory ancestry changed")


@contextmanager
def _windows_pinned_directory_chain(
    path: Path,
) -> Iterator[tuple[tuple[Path, tuple[int, ...]], ...]]:
    """Pin root through parent without delete sharing during publication."""

    if os.name != "nt":
        yield ()
        return
    import ctypes
    from ctypes import wintypes

    absolute = Path(os.path.abspath(os.fspath(path)))
    if not absolute.anchor or absolute.anchor.startswith("\\\\"):
        raise OSError("Windows profile directory ancestry is unsupported")
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    close_handle = kernel32.CloseHandle
    close_handle.argtypes = (wintypes.HANDLE,)
    close_handle.restype = wintypes.BOOL

    class _FileAttributeTagInformation(ctypes.Structure):
        _fields_ = [
            ("file_attributes", wintypes.DWORD),
            ("reparse_tag", wintypes.DWORD),
        ]

    get_information = kernel32.GetFileInformationByHandleEx
    get_information.argtypes = (
        wintypes.HANDLE,
        ctypes.c_int,
        ctypes.c_void_p,
        wintypes.DWORD,
    )
    get_information.restype = wintypes.BOOL

    handles: list[int] = []
    captured: list[tuple[Path, tuple[int, ...]]] = []
    current = Path(absolute.anchor)
    try:
        for part in (None, *absolute.parts[1:]):
            if part is not None:
                current /= part
            opened = create_file(
                os.fspath(current),
                0x00020000 | 0x00000080,
                # READ_CONTROL | FILE_READ_ATTRIBUTES
                0x00000001 | 0x00000002,
                # FILE_SHARE_READ | FILE_SHARE_WRITE; no FILE_SHARE_DELETE
                None,
                3,  # OPEN_EXISTING
                0x02000000 | 0x00200000,
                # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
                None,
            )
            invalid_handle = ctypes.c_void_p(-1).value
            if opened in {None, invalid_handle}:
                raise win_error(get_last_error())
            handle = int(opened)
            handles.append(handle)
            attributes = _FileAttributeTagInformation()
            if not get_information(
                wintypes.HANDLE(handle),
                9,  # FileAttributeTagInfo
                ctypes.byref(attributes),
                ctypes.sizeof(attributes),
            ):
                raise win_error(get_last_error())
            information = current.lstat()
            final_path = _windows_native_handle_final_path(handle)
            final_information = final_path.lstat()
            lexical = os.path.normcase(
                os.path.normpath(os.path.abspath(os.fspath(current)))
            )
            final = os.path.normcase(
                os.path.normpath(os.path.abspath(os.fspath(final_path)))
            )
            if (
                int(attributes.file_attributes) & 0x00000400
                or stat.S_ISLNK(information.st_mode)
                or stat.S_ISLNK(final_information.st_mode)
                or not stat.S_ISDIR(information.st_mode)
                or not stat.S_ISDIR(final_information.st_mode)
                or _windows_directory_identity(information)
                != _windows_directory_identity(final_information)
                or lexical != final
                or not _windows_handle_namespace_dacl_is_safe(handle)
            ):
                raise OSError("Windows profile directory ancestry is unsafe")
            captured.append((current, _windows_directory_identity(information)))
        result = tuple(captured)
        yield result
        _recheck_windows_directory_chain(result)
    finally:
        for handle in reversed(handles):
            close_handle(wintypes.HANDLE(handle))


def _windows_open_directory_handle(path: Path, *, write_dacl: bool = False) -> int:
    """Open one directory without following its entry or sharing deletion."""

    if os.name != "nt":
        raise OSError("Windows directory APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    access = 0x00020000 | 0x00000080  # READ_CONTROL | FILE_READ_ATTRIBUTES
    if write_dacl:
        access |= 0x00040000  # WRITE_DAC
    opened = create_file(
        os.fspath(path),
        access,
        0x00000001 | 0x00000002,  # SHARE_READ | SHARE_WRITE; no SHARE_DELETE
        None,
        3,  # OPEN_EXISTING
        0x02000000 | 0x00200000,
        # FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if opened in {None, invalid_handle}:
        raise win_error(get_last_error())
    return int(opened)


def _windows_verify_private_directory(path: Path) -> None:
    """Require an exact current-user/System protected inheritable DACL."""

    import ctypes
    from ctypes import wintypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    handle = _windows_open_directory_handle(path)
    try:
        information = path.lstat()
        final_path = _windows_native_handle_final_path(handle)
        owner, dacl = _windows_handle_security(handle)
        expected_owner, expected_dacl = _windows_expected_private_security(
            directory=True
        )
        reparse_attribute = int(
            getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400)
        )
        lexical = os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))
        final = os.path.normcase(
            os.path.normpath(os.path.abspath(os.fspath(final_path)))
        )
        if (
            stat.S_ISLNK(information.st_mode)
            or bool(
                int(getattr(information, "st_file_attributes", 0)) & reparse_attribute
            )
            or not stat.S_ISDIR(information.st_mode)
            or lexical != final
            or owner != expected_owner
            or dacl != expected_dacl
        ):
            raise OSError("Windows private directory identity or DACL is unsafe")
    finally:
        kernel32.CloseHandle(wintypes.HANDLE(handle))


def _windows_harden_private_directory(path: Path) -> None:
    """Canonicalize a current-user-owned directory through its pinned handle."""

    if os.name != "nt":
        raise OSError("Windows directory APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    advapi32.GetSecurityDescriptorDacl.argtypes = (
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.BOOL),
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.BOOL),
    )
    advapi32.GetSecurityDescriptorDacl.restype = wintypes.BOOL
    advapi32.SetSecurityInfo.argtypes = (
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_void_p,
    )
    advapi32.SetSecurityInfo.restype = wintypes.DWORD

    with _windows_pinned_directory_chain(path.parent):
        handle = _windows_open_directory_handle(path, write_dacl=True)
        try:
            expected = _windows_expected_private_security(directory=True)
            actual_owner, _actual_dacl = _windows_handle_security(
                handle,
                require_protected=False,
            )
            if actual_owner != expected[0]:
                raise OSError("Windows private directory owner is unsafe")
            current_sid = _windows_current_user_sid_string()
            security_descriptor = ctypes.c_void_p()
            sddl = f"O:{current_sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{current_sid})"
            if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl,
                1,
                ctypes.byref(security_descriptor),
                None,
            ):
                raise win_error(get_last_error())
            try:
                present = wintypes.BOOL()
                defaulted = wintypes.BOOL()
                dacl = ctypes.c_void_p()
                if (
                    not advapi32.GetSecurityDescriptorDacl(
                        security_descriptor,
                        ctypes.byref(present),
                        ctypes.byref(dacl),
                        ctypes.byref(defaulted),
                    )
                    or not present.value
                    or not dacl.value
                ):
                    raise OSError("Windows private directory DACL is invalid")
                result = advapi32.SetSecurityInfo(
                    wintypes.HANDLE(handle),
                    1,  # SE_FILE_OBJECT
                    0x00000004 | 0x80000000,
                    # DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION
                    None,
                    None,
                    dacl,
                    None,
                )
                if result != 0:
                    raise win_error(result)
            finally:
                kernel32.LocalFree(security_descriptor)
            hardened_owner, hardened_dacl = _windows_handle_security(handle)
            if hardened_owner != expected[0] or hardened_dacl != expected[1]:
                raise OSError("Windows private directory DACL hardening failed")
        finally:
            kernel32.CloseHandle(wintypes.HANDLE(handle))


def _windows_create_private_directory(path: Path) -> None:
    """Create a directory with its protected inheritable DACL already present."""

    if os.name != "nt" or not path.is_absolute():
        raise OSError("atomic Windows private-directory creation is unavailable")
    import ctypes
    from ctypes import wintypes

    advapi32 = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")

    class _SecurityAttributes(ctypes.Structure):
        _fields_ = [
            ("length", wintypes.DWORD),
            ("security_descriptor", ctypes.c_void_p),
            ("inherit_handle", wintypes.BOOL),
        ]

    kernel32.LocalFree.argtypes = (ctypes.c_void_p,)
    kernel32.LocalFree.restype = ctypes.c_void_p
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    )
    advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = (
        wintypes.BOOL
    )
    create_directory = kernel32.CreateDirectoryW
    create_directory.argtypes = (
        wintypes.LPCWSTR,
        ctypes.POINTER(_SecurityAttributes),
    )
    create_directory.restype = wintypes.BOOL

    current_sid = _windows_current_user_sid_string()
    security_descriptor = ctypes.c_void_p()
    sddl = f"O:{current_sid}D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{current_sid})"
    if not advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
        sddl,
        1,
        ctypes.byref(security_descriptor),
        None,
    ):
        raise win_error(get_last_error())
    try:
        attributes = _SecurityAttributes(
            ctypes.sizeof(_SecurityAttributes),
            security_descriptor,
            False,
        )
        if not create_directory(os.fspath(path), ctypes.byref(attributes)):
            error = int(get_last_error())
            if error in {80, 183}:  # ERROR_FILE_EXISTS / ERROR_ALREADY_EXISTS
                raise FileExistsError(
                    error,
                    "private directory already exists",
                    os.fspath(path),
                )
            raise win_error(error)
    finally:
        kernel32.LocalFree(security_descriptor)
    try:
        _windows_verify_private_directory(path)
    except Exception:
        try:
            path.rmdir()
        except OSError:
            pass
        raise


def _windows_ensure_private_directory(
    path: Path,
    *,
    harden_existing: bool = True,
) -> Path:
    """Create missing directory edges privately and validate the final leaf.

    ``harden_existing`` is reserved for state directories Echo Veil owns. Public
    stores pass ``False`` so a caller-supplied shared directory is rejected
    rather than silently having its DACL replaced.
    """

    if os.name != "nt":
        raise OSError("Windows directory APIs are unavailable")
    absolute = Path(os.path.abspath(os.fspath(path)))
    if (
        not absolute.anchor
        or absolute.anchor.startswith("\\\\")
        or absolute == Path(absolute.anchor)
    ):
        raise OSError("Windows private directory boundary is unsupported")
    missing: list[Path] = []
    current = absolute
    while not current.exists():
        missing.append(current)
        parent = current.parent
        if parent == current:
            raise OSError("Windows private directory has no existing boundary")
        current = parent
    if current.is_symlink() or not current.is_dir():
        raise OSError("Windows private directory boundary is unsafe")
    for candidate in reversed(missing):
        with _windows_pinned_directory_chain(candidate.parent):
            try:
                _windows_create_private_directory(candidate)
            except FileExistsError:
                # A racing creator is acceptable only if it produced the exact
                # protected current-user/System directory contract.
                _windows_verify_private_directory(candidate)
    try:
        _windows_verify_private_directory(absolute)
    except OSError:
        if not harden_existing:
            raise
        _windows_harden_private_directory(absolute)
        _windows_verify_private_directory(absolute)
    with _windows_pinned_directory_chain(absolute):
        # Bind the exact private leaf proof to the same full-chain pin. A
        # trusted but broad-readable replacement is not sufficient here.
        _windows_verify_private_directory(absolute)
    return absolute


def _windows_descriptor_final_path(descriptor: int) -> Path:
    """Return the normalized DOS path bound to one open CRT descriptor."""

    if os.name != "nt":
        raise OSError("Windows path APIs are unavailable")
    import msvcrt

    return _windows_native_handle_final_path(
        int(getattr(msvcrt, "get_osfhandle")(descriptor))
    )


def _windows_verify_descriptor(
    descriptor: int,
    path: Path,
    *,
    expected_payload: bytes | None,
    expected_state: _WindowsFileState | None = None,
    expected_security: tuple[bytes, bytes] | None = None,
    require_protected_security: bool = True,
) -> _WindowsFileState:
    """Verify bytes, name binding, type, link count, identity, and DACL."""

    path_information = path.lstat()
    descriptor_information = os.fstat(descriptor)
    reparse_attribute = int(getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x00000400))
    final_path = _windows_descriptor_final_path(descriptor)
    lexical = os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(path))))
    final = os.path.normcase(os.path.normpath(os.path.abspath(os.fspath(final_path))))
    identity = _windows_file_identity(descriptor_information)
    security = _windows_descriptor_security(
        descriptor,
        require_protected=require_protected_security,
    )
    if (
        stat.S_ISLNK(path_information.st_mode)
        or bool(
            int(getattr(path_information, "st_file_attributes", 0)) & reparse_attribute
        )
        or not stat.S_ISREG(path_information.st_mode)
        or not stat.S_ISREG(descriptor_information.st_mode)
        or descriptor_information.st_nlink != 1
        or _windows_file_identity(path_information) != identity
        or lexical != final
        or (expected_state is not None and expected_state.identity != identity)
        or (
            expected_state is not None
            and (expected_state.owner, expected_state.dacl) != security
        )
        or (expected_security is not None and expected_security != security)
    ):
        raise OSError("Windows profile manifest file identity is unsafe")

    if expected_payload is not None:
        position = os.lseek(descriptor, 0, os.SEEK_CUR)
        os.lseek(descriptor, 0, os.SEEK_SET)
        try:
            chunks: list[bytes] = []
            remaining = len(expected_payload) + 1
            while remaining > 0:
                chunk = os.read(descriptor, min(65_536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
        finally:
            os.lseek(descriptor, position, os.SEEK_SET)
        if b"".join(chunks) != expected_payload:
            raise OSError("Windows profile manifest bytes failed verification")
    return _WindowsFileState(identity=identity, owner=security[0], dacl=security[1])


def _windows_open_private_file(
    path: Path,
    *,
    writable: bool,
    share_write: bool = False,
) -> int:
    """Open a non-reparse private file without write/delete sharing."""

    if os.name != "nt":
        raise OSError("Windows file APIs are unavailable")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    access = 0x80000000 | 0x00020000  # GENERIC_READ | READ_CONTROL
    if writable:
        access |= 0x40000000  # GENERIC_WRITE
    share_mode = 0x00000001  # FILE_SHARE_READ
    if share_write:
        share_mode |= 0x00000002  # FILE_SHARE_WRITE
    opened = create_file(
        os.fspath(path),
        access,
        share_mode,  # Deliberately never share deletion/name replacement.
        None,
        3,  # OPEN_EXISTING
        0x00000080 | 0x00200000,
        # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if opened in {None, invalid_handle}:
        raise win_error(get_last_error())
    handle: int | None = int(opened)
    try:
        descriptor = int(
            getattr(msvcrt, "open_osfhandle")(
                handle,
                (os.O_RDWR if writable else os.O_RDONLY)
                | int(getattr(os, "O_BINARY", 0))
                | int(getattr(os, "O_NOINHERIT", 0)),
            )
        )
        handle = None
        return descriptor
    finally:
        if handle is not None:
            kernel32.CloseHandle(wintypes.HANDLE(handle))


def _windows_move_file_replace_write_through(source: Path, destination: Path) -> None:
    """Atomically replace one same-volume file and flush rename metadata."""

    if os.name != "nt":
        raise OSError("Windows move APIs are unavailable")
    import ctypes
    from ctypes import wintypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    move_file = kernel32.MoveFileExW
    move_file.argtypes = (wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD)
    move_file.restype = wintypes.BOOL
    flags = 0x00000001 | 0x00000008
    # MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH. Deliberately omit
    # MOVEFILE_COPY_ALLOWED so a cross-volume fallback can never occur.
    if not move_file(os.fspath(source), os.fspath(destination), flags):
        raise win_error(get_last_error())


def _windows_verify_publication(
    path: Path,
    *,
    expected_payload: bytes,
    expected_state: _WindowsFileState,
) -> None:
    """Open the published name without delete sharing and verify exact state."""

    if os.name != "nt":
        raise OSError("Windows file APIs are unavailable")
    import ctypes
    import msvcrt
    from ctypes import wintypes

    kernel32 = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    get_last_error = getattr(ctypes, "get_last_error")
    win_error = getattr(ctypes, "WinError")
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    kernel32.CloseHandle.restype = wintypes.BOOL
    create_file = kernel32.CreateFileW
    create_file.argtypes = (
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    )
    create_file.restype = wintypes.HANDLE
    opened = create_file(
        os.fspath(path),
        0x80000000 | 0x00020000,  # GENERIC_READ | READ_CONTROL
        0x00000001,  # FILE_SHARE_READ; deliberately no write/delete sharing
        None,
        3,  # OPEN_EXISTING
        0x00000080 | 0x00200000,
        # FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT
        None,
    )
    invalid_handle = ctypes.c_void_p(-1).value
    if opened in {None, invalid_handle}:
        raise win_error(get_last_error())
    handle: int | None = int(opened)
    descriptor = -1
    try:
        try:
            descriptor = int(
                getattr(msvcrt, "open_osfhandle")(
                    handle,
                    os.O_RDONLY
                    | int(getattr(os, "O_BINARY", 0))
                    | int(getattr(os, "O_NOINHERIT", 0)),
                )
            )
        except Exception:
            kernel32.CloseHandle(wintypes.HANDLE(handle))
            handle = None
            raise
        handle = None
        _windows_verify_descriptor(
            descriptor,
            path,
            expected_payload=expected_payload,
            expected_state=expected_state,
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        elif handle is not None:
            kernel32.CloseHandle(wintypes.HANDLE(handle))


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
        self._keys: dict[str, bytes | CustodyDescriptor] = {}
        self._custody_clients: dict[str, CustodyClient] = {}
        self._derived_keys: dict[tuple[str, str, int], bytes] = {}
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

    @property
    def custody_provider(self) -> str:
        """Return the active root's real provider without inferring readiness."""

        value = self._keys.get(self.active_key_id)
        return (
            value.provider if isinstance(value, CustodyDescriptor) else FILE_CUSTODY_V1
        )

    @property
    def raw_active_key_present(self) -> bool:
        """Report whether normal profile files still contain the active root."""

        keys_dir = self.profile_dir / "keys"
        return (
            any(
                path.is_file() and path.name.endswith(".key")
                for path in keys_dir.glob("*.key")
            )
            if keys_dir.is_dir()
            else False
        )

    def _custody_descriptor_path(self, reference: str) -> Path:
        if _CUSTODY_REF_RE.fullmatch(reference) is None:
            raise KeyUnavailable("key-custody reference is invalid")
        return self.profile_dir / "custody" / f"{reference}.json"

    def _custody_activation_receipt_path(self) -> Path:
        return self.profile_dir / "custody" / "activation-receipt.json"

    @staticmethod
    def _custody_authentication_message(descriptor: CustodyDescriptor) -> bytes:
        return (
            b"echo-veil-key-custody-descriptor-v1\0"
            + descriptor.authentication_message()
        )

    @staticmethod
    def _custody_activation_message(
        *,
        reference: str,
        process_instance: str,
    ) -> bytes:
        if _CUSTODY_REF_RE.fullmatch(reference) is None:
            raise KeyUnavailable("key-custody activation reference is invalid")
        if _PROCESS_INSTANCE_RE.fullmatch(process_instance) is None:
            raise KeyUnavailable("key-custody activation process is invalid")
        return (
            b"echo-veil-custody-activation-v1\0"
            + reference.encode("ascii")
            + b"\0"
            + process_instance.encode("ascii")
        )

    def _write_custody_activation_receipt(
        self,
        descriptor: CustodyDescriptor,
        client: CustodyClient,
    ) -> None:
        message = self._custody_activation_message(
            reference=descriptor.reference,
            process_instance=_PROCESS_INSTANCE_ID,
        )
        _atomic_write_json(
            self._custody_activation_receipt_path(),
            {
                "process_instance": _PROCESS_INSTANCE_ID,
                "reference": descriptor.reference,
                "schema": _CUSTODY_ACTIVATION_SCHEMA,
                "tag": client.root_hmac(message).hex(),
            },
        )

    def _verified_custody_activation_process(
        self,
        descriptor: CustodyDescriptor,
        client: CustodyClient,
    ) -> str:
        try:
            raw = _read_private_file_bytes(
                self._custody_activation_receipt_path(),
                label="key-custody activation receipt",
                maximum=4096,
            )
            decoded = strict_json_loads(raw)
        except Exception as exc:
            raise KeyUnavailable(
                "key-custody activation receipt is unavailable"
            ) from exc
        if not isinstance(decoded, dict) or set(decoded) != {
            "process_instance",
            "reference",
            "schema",
            "tag",
        }:
            raise KeyUnavailable("key-custody activation receipt is invalid")
        if (
            decoded["schema"] != _CUSTODY_ACTIVATION_SCHEMA
            or decoded["reference"] != descriptor.reference
        ):
            raise KeyUnavailable("key-custody activation receipt is invalid")
        process_instance = decoded["process_instance"]
        tag = decoded["tag"]
        if (
            not isinstance(process_instance, str)
            or _PROCESS_INSTANCE_RE.fullmatch(process_instance) is None
            or not isinstance(tag, str)
            or re.fullmatch(r"[0-9a-f]{64}", tag) is None
        ):
            raise KeyUnavailable("key-custody activation receipt is invalid")
        expected = client.root_hmac(
            self._custody_activation_message(
                reference=descriptor.reference,
                process_instance=process_instance,
            )
        ).hex()
        if not hmac.compare_digest(expected, tag):
            raise KeyUnavailable("key-custody activation receipt authentication failed")
        return process_instance

    def _client_for(self, key_id: str) -> CustodyClient:
        clean_id = _validate_key_id(key_id)
        existing = self._custody_clients.get(clean_id)
        if existing is not None:
            return existing
        value = self._keys.get(clean_id)
        if not isinstance(value, CustodyDescriptor):
            raise KeyUnavailable("profile key does not use opaque custody")
        try:
            client: CustodyClient = MacOSKeyCustodyClient(value, self.profile_dir)
            probe = client.probe()
        except Exception as exc:
            raise KeyUnavailable("opaque profile key is unavailable") from exc
        if probe.get("key_id") != clean_id:
            client.close()
            raise KeyUnavailable("opaque profile key identity changed")
        self._custody_clients[clean_id] = client
        return client

    def _root_hmac(self, key_id: str, message: bytes) -> bytes:
        value = self._keys.get(_validate_key_id(key_id))
        if isinstance(value, bytes):
            return hmac.new(value, message, hashlib.sha256).digest()
        if isinstance(value, CustodyDescriptor):
            return self._client_for(key_id).root_hmac(message)
        raise KeyUnavailable("required profile key is unavailable")

    def _scope_binding_for_manifest(
        self,
        key_id: str,
        manifest: dict[str, Any],
    ) -> str:
        message = _scope_binding_message(
            self.scope,
            _validate_scope_id(manifest["scope_id"]),
            features=tuple(str(item) for item in manifest.get("features", [])),
            key_epochs=self._key_epochs_from_manifest(manifest),
        )
        return self._root_hmac(key_id, message).hex()

    @property
    def features(self) -> tuple[str, ...]:
        raw = self._manifest.get("features", [])
        if not isinstance(raw, list):
            raise KeyUnavailable("profile key manifest features are invalid")
        return tuple(str(feature) for feature in raw)

    @property
    def record_envelope_write_version(self) -> int:
        """Return the internal write envelope without changing protocol versions."""

        return (
            RECORD_ENVELOPE_V3
            if RECORD_ENVELOPE_V3_FEATURE in self.features
            else RECORD_ENVELOPE_V2
        )

    def has_feature(self, feature: str) -> bool:
        if feature not in SUPPORTED_PROFILE_FEATURES:
            raise ValueError("profile feature is unsupported")
        return feature in self.features

    def enable_feature(self, feature: str) -> None:
        if feature not in SUPPORTED_PROFILE_FEATURES:
            raise ValueError("profile feature is unsupported")
        if feature == RECORD_ENVELOPE_V3_FEATURE:
            self.enable_record_envelope_v3()
            return
        if feature in self.features:
            return
        features = tuple(sorted((*self.features, feature)))
        manifest = copy.deepcopy(self._manifest)
        manifest["features"] = list(features)
        manifest["scope_binding"] = self._scope_binding_for_manifest(
            self.active_key_id,
            manifest,
        )
        _atomic_write_json(self.manifest_path, manifest)
        self._manifest = manifest

    def enable_record_envelope_v3(self) -> None:
        """Persist the v3 downgrade barrier and initial root-key epoch."""

        if self.rotation_state is not None:
            raise RuntimeError(
                "record-envelope activation requires a completed key rotation"
            )
        if RECORD_ENVELOPE_V3_FEATURE in self.features:
            return
        manifest = copy.deepcopy(self._manifest)
        keys = manifest.get("keys")
        if not isinstance(keys, dict) or set(keys) != {self.active_key_id}:
            raise KeyUnavailable(
                "record-envelope activation requires one verified active key"
            )
        entry = keys[self.active_key_id]
        if not isinstance(entry, dict) or set(entry) != {"ref", "status"}:
            raise KeyUnavailable("profile key reference is invalid")
        entry["epoch"] = 1
        features = tuple(sorted((*self.features, RECORD_ENVELOPE_V3_FEATURE)))
        manifest["features"] = list(features)
        manifest["scope_binding"] = self._scope_binding_for_manifest(
            self.active_key_id,
            manifest,
        )
        _atomic_write_json(self.manifest_path, manifest)
        self._manifest = manifest

    def key_epoch(self, key_id: str) -> int:
        """Return the authenticated v3 epoch for a referenced root key."""

        clean_id = _validate_key_id(key_id)
        if RECORD_ENVELOPE_V3_FEATURE not in self.features:
            raise KeyUnavailable("record-envelope v3 key epochs are unavailable")
        keys = self._manifest.get("keys")
        entry = keys.get(clean_id) if isinstance(keys, dict) else None
        epoch = entry.get("epoch") if isinstance(entry, dict) else None
        if (
            isinstance(epoch, bool)
            or not isinstance(epoch, int)
            or not 1 <= epoch <= 2**31 - 1
        ):
            raise KeyUnavailable("profile key epoch is invalid")
        return epoch

    def key_for_envelope(
        self,
        key_id: str,
        *,
        purpose: str,
        envelope_version: int,
    ) -> bytes:
        """Return the legacy root key or one purpose-separated v3 subkey."""

        clean_id = _validate_key_id(key_id)
        if envelope_version == RECORD_ENVELOPE_V2:
            return self.key(clean_id)
        if envelope_version != RECORD_ENVELOPE_V3:
            raise KeyUnavailable("record-envelope version is unsupported")
        epoch = self.key_epoch(clean_id)
        cache_key = (clean_id, purpose, epoch)
        cached = self._derived_keys.get(cache_key)
        if cached is not None:
            return cached
        material = self._keys.get(clean_id)
        if isinstance(material, bytes):
            derived = derive_record_envelope_key(
                material,
                profile_scope=self.scope,
                scope_id=self.scope_id,
                key_epoch=epoch,
                purpose=purpose,
                envelope_version=envelope_version,
                algorithm=RECORD_ENVELOPE_V3_ALGORITHM,
            )
        elif isinstance(material, CustodyDescriptor):
            derived = self._client_for(clean_id).derive_v3_key(
                profile_scope=self.scope,
                scope_id=self.scope_id,
                key_epoch=epoch,
                purpose=purpose,
            )
        else:
            raise KeyUnavailable("required profile key is unavailable")
        self._derived_keys[cache_key] = derived
        return derived

    def pre_migration_backup_key(self, key_id: str) -> bytes:
        """Derive the envelope-v2 recovery key without exporting opaque roots."""

        clean_id = _validate_key_id(key_id)
        message = (
            b"echo-veil-pre-migration-backup-key-v1\0"
            + self.scope.encode("utf-8")
            + b"\0"
            + self.scope_id.encode("ascii")
            + b"\0"
            + clean_id.encode("ascii")
            + b"\0record-envelope-v2\0"
            + KEY_PURPOSE_BACKUP_MANIFEST.encode("ascii")
        )
        return self._root_hmac(clean_id, message)

    def lsh_index_key(self) -> bytes:
        """Derive the active profile's separately versioned LSH key."""

        if RECORD_ENVELOPE_V3_FEATURE in self.features:
            return self.key_for_envelope(
                self.active_key_id,
                purpose=KEY_PURPOSE_LSH_INDEX,
                envelope_version=RECORD_ENVELOPE_V3,
            )
        return hmac.new(
            self.active_key(),
            b"echo-veil-lsh-index-key-v2\0"
            + self.scope_id.encode("ascii")
            + b"\0"
            + self.scope.encode("utf-8"),
            hashlib.sha256,
        ).digest()

    def export_portable_root(self, *, recovery_key: bytes, context: bytes) -> bytes:
        """Return only a recovery-key-wrapped root from opaque native custody."""

        value = self._keys.get(self.active_key_id)
        if not isinstance(value, CustodyDescriptor):
            raise RuntimeError("portable root export requires opaque key custody")
        if value.state != "active":
            raise RuntimeError("portable root export requires active key custody")
        return self._client_for(self.active_key_id).export_portable(
            recovery_key=recovery_key,
            context=context,
        )

    def monotonic_generation(self) -> int | None:
        """Return the device-local generation, or None for file custody."""

        value = self._keys.get(self.active_key_id)
        if not isinstance(value, CustodyDescriptor):
            return None
        return self._client_for(self.active_key_id).generation()

    def advance_monotonic_generation(self, *, expected: int, new: int) -> int:
        value = self._keys.get(self.active_key_id)
        if not isinstance(value, CustodyDescriptor) or value.state != "active":
            raise RuntimeError(
                "local monotonic generation requires active opaque custody"
            )
        return self._client_for(self.active_key_id).advance_generation(
            expected=expected,
            new=new,
        )

    def destroy_opaque_custody_for_restore_drill(self, *, confirm: bool) -> None:
        """Delete a temporary portable-restore item; never use on a live profile."""

        if confirm is not True:
            raise ValueError("restore-drill custody deletion requires confirm=true")
        value = self._keys.get(self.active_key_id)
        if not isinstance(value, CustodyDescriptor):
            raise RuntimeError("restore-drill profile does not use opaque custody")
        client = self._client_for(self.active_key_id)
        client.delete(confirm=True)

    @staticmethod
    def _key_epochs_from_manifest(
        manifest: dict[str, Any],
    ) -> tuple[tuple[str, int], ...]:
        features = manifest.get("features", [])
        if RECORD_ENVELOPE_V3_FEATURE not in features:
            return ()
        keys = manifest.get("keys")
        if not isinstance(keys, dict):
            raise KeyUnavailable("profile key references are invalid")
        epochs: list[tuple[str, int]] = []
        for key_id in sorted(keys):
            entry = keys[key_id]
            epoch = entry.get("epoch") if isinstance(entry, dict) else None
            if (
                isinstance(epoch, bool)
                or not isinstance(epoch, int)
                or not 1 <= epoch <= 2**31 - 1
            ):
                raise KeyUnavailable("profile key epoch is invalid")
            epochs.append((_validate_key_id(key_id), epoch))
        if len({epoch for _key_id, epoch in epochs}) != len(epochs):
            raise KeyUnavailable("profile key epochs must be unique")
        return tuple(epochs)

    def key(self, key_id: str) -> bytes:
        clean_id = _validate_key_id(key_id)
        try:
            value = self._keys[clean_id]
        except KeyError as exc:
            raise KeyUnavailable("required profile key is unavailable") from exc
        if not isinstance(value, bytes):
            raise KeyUnavailable("opaque profile roots cannot be exported")
        return value

    def active_key(self) -> bytes:
        return self.key(self.active_key_id)

    @property
    def custody_state(self) -> str:
        value = self._keys.get(self.active_key_id)
        return value.state if isinstance(value, CustodyDescriptor) else "file"

    def prepare_custody_migration(
        self,
        *,
        provider: str,
        helper_path: Path,
        backup_verified: bool,
    ) -> dict[str, str]:
        """Copy the active v3 root into native custody without switching reads.

        The raw file remains authoritative until ``activate_custody_migration``
        verifies every derived domain.  A later, separately confirmed call
        removes that raw file.  Callers must derive ``backup_verified`` from the
        authenticated backup verifier; user input is not readiness evidence.
        """

        if backup_verified is not True:
            raise ValueError("key-custody migration requires a verified backup")
        if provider not in OPAQUE_KEY_CUSTODY:
            raise ValueError("key-custody provider is unsupported")
        if RECORD_ENVELOPE_V3_FEATURE not in self.features:
            raise RuntimeError("key custody requires record-envelope v3")
        if self.rotation_state is not None:
            raise RuntimeError("key custody requires a completed key rotation")
        if self.custody_provider != FILE_CUSTODY_V1:
            raise RuntimeError("active profile key already uses opaque custody")
        root = self.active_key()
        key_id = self.active_key_id
        reference = f"evkc-{os.urandom(16).hex()}"
        absolute_helper = Path(os.path.abspath(os.fspath(helper_path)))
        digest, cdhash = helper_identity(absolute_helper)
        descriptor = CustodyDescriptor(
            provider=provider,
            reference=reference,
            key_id=key_id,
            helper_path=absolute_helper,
            helper_sha256=digest,
            helper_cdhash=cdhash,
            peer_cdhash=executable_cdhash(),
            state="prepared",
        )
        custody_dir = _secure_directory(self.profile_dir / "custody")
        descriptor_path = custody_dir / f"{reference}.json"
        client: CustodyClient = MacOSKeyCustodyClient(descriptor, self.profile_dir)
        imported = False
        try:
            if client.import_root(root) != key_id:
                raise KeyUnavailable("native custody changed the profile key ID")
            imported = True
            for purpose in sorted(RECORD_ENVELOPE_KEY_PURPOSES):
                native = client.derive_v3_key(
                    profile_scope=self.scope,
                    scope_id=self.scope_id,
                    key_epoch=self.key_epoch(key_id),
                    purpose=purpose,
                )
                expected = derive_record_envelope_key(
                    root,
                    profile_scope=self.scope,
                    scope_id=self.scope_id,
                    key_epoch=self.key_epoch(key_id),
                    purpose=purpose,
                )
                if not hmac.compare_digest(native, expected):
                    raise KeyUnavailable("native custody key derivation mismatch")
            tag = client.root_hmac(
                self._custody_authentication_message(descriptor)
            ).hex()
            _atomic_write_json(descriptor_path, descriptor.as_dict(tag_hex=tag))
        except Exception:
            if imported:
                try:
                    client.delete(confirm=True)
                except Exception:
                    pass
            try:
                _unlink_private_file(
                    descriptor_path,
                    label="unactivated key-custody descriptor",
                )
            except (KeyUnavailable, OSError):
                pass
            raise
        finally:
            client.close()
        return {
            "provider": provider,
            "reference": reference,
            "state": "prepared",
        }

    def _prepared_custody_descriptor(self) -> tuple[CustodyDescriptor, str, Path]:
        custody_dir = self.profile_dir / "custody"
        if not custody_dir.is_dir():
            raise RuntimeError("no key-custody migration is prepared")
        candidates = tuple(custody_dir.glob("evkc-*.json"))
        prepared: list[tuple[CustodyDescriptor, str, Path]] = []
        for path in candidates:
            raw = _read_private_file_bytes(
                path,
                label="key-custody descriptor",
                maximum=64 * 1024,
            )
            descriptor, tag = CustodyDescriptor.from_json_bytes(raw)
            if descriptor.key_id == self.active_key_id and descriptor.state in {
                "prepared",
                "verified",
            }:
                prepared.append((descriptor, tag, path))
        if len(prepared) != 1:
            raise RuntimeError("key-custody migration state is ambiguous")
        return prepared[0]

    def activate_custody_migration(self, *, confirm: bool) -> dict[str, str]:
        """Switch the manifest to a fully verified opaque root reference."""

        if confirm is not True:
            raise ValueError("key-custody activation requires confirm=true")
        if self.custody_provider != FILE_CUSTODY_V1:
            value = self._keys.get(self.active_key_id)
            if isinstance(value, CustodyDescriptor):
                if value.state == "verified":
                    self._verified_custody_activation_process(
                        value,
                        self._client_for(self.active_key_id),
                    )
                return {"provider": value.provider, "state": value.state}
            raise RuntimeError("active key-custody state is invalid")
        descriptor, stored_tag, descriptor_path = self._prepared_custody_descriptor()
        root = self.active_key()
        client: CustodyClient = MacOSKeyCustodyClient(descriptor, self.profile_dir)
        retain_client = False
        try:
            probe = client.probe()
            if probe.get("key_id") != self.active_key_id:
                raise KeyUnavailable("native custody key identity changed")
            expected_tag = client.root_hmac(
                self._custody_authentication_message(descriptor)
            ).hex()
            if not hmac.compare_digest(stored_tag, expected_tag):
                raise KeyUnavailable("key-custody descriptor authentication failed")
            for purpose in sorted(RECORD_ENVELOPE_KEY_PURPOSES):
                native = client.derive_v3_key(
                    profile_scope=self.scope,
                    scope_id=self.scope_id,
                    key_epoch=self.key_epoch(self.active_key_id),
                    purpose=purpose,
                )
                expected = derive_record_envelope_key(
                    root,
                    profile_scope=self.scope,
                    scope_id=self.scope_id,
                    key_epoch=self.key_epoch(self.active_key_id),
                    purpose=purpose,
                )
                if not hmac.compare_digest(native, expected):
                    raise KeyUnavailable("native custody verification failed")
            verified = replace(descriptor, state="verified")
            verified_tag = client.root_hmac(
                self._custody_authentication_message(verified)
            ).hex()
            _atomic_write_json(
                descriptor_path,
                verified.as_dict(tag_hex=verified_tag),
            )
            self._write_custody_activation_receipt(verified, client)
            manifest = copy.deepcopy(self._manifest)
            keys = manifest.get("keys")
            entry = keys.get(self.active_key_id) if isinstance(keys, dict) else None
            if not isinstance(entry, dict):
                raise KeyUnavailable("active profile key reference is invalid")
            epoch = entry.get("epoch")
            manifest["keys"][self.active_key_id] = {
                "epoch": epoch,
                "provider": verified.provider,
                "ref": verified.reference,
                "status": "active",
            }
            # The root is unchanged, so the existing scope binding remains valid.
            _atomic_write_json(self.manifest_path, manifest)
            self._manifest = manifest
            self._keys[self.active_key_id] = verified
            self._custody_clients[self.active_key_id] = client
            retain_client = True
            self._derived_keys.clear()
        finally:
            if not retain_client:
                client.close()
        return {"provider": descriptor.provider, "state": "verified"}

    def retire_file_custody(self, *, confirm: bool) -> dict[str, str]:
        """Remove the raw root only after opaque custody is active and verified."""

        if confirm is not True:
            raise ValueError("file-custody retirement requires confirm=true")
        value = self._keys.get(self.active_key_id)
        if not isinstance(value, CustodyDescriptor) or value.state not in {
            "active",
            "verified",
        }:
            raise RuntimeError("key-custody migration is not verified")
        client = self._client_for(self.active_key_id)
        if client.probe().get("key_id") != self.active_key_id:
            raise KeyUnavailable("native custody key identity changed")
        receipt_path = self._custody_activation_receipt_path()
        if value.state == "verified":
            activated_by = self._verified_custody_activation_process(value, client)
            if hmac.compare_digest(activated_by, _PROCESS_INSTANCE_ID):
                raise RuntimeError(
                    "file-custody retirement requires a fresh-process verification"
                )
        key_path = self.profile_dir / "keys" / f"{self.active_key_id}.key"
        active = value
        if value.state == "verified":
            active = replace(value, state="active")
            tag = client.root_hmac(self._custody_authentication_message(active)).hex()
            _atomic_write_json(
                self._custody_descriptor_path(active.reference),
                active.as_dict(tag_hex=tag),
            )
            self._keys[self.active_key_id] = active
        try:
            key = _read_key(key_path)
        except FileNotFoundError:
            if value.state == "verified":
                raise KeyUnavailable(
                    "verified custody migration lost its recoverable file root"
                ) from None
        else:
            if not hmac.compare_digest(key_id_for(key), self.active_key_id):
                raise KeyUnavailable("retired file root does not match active custody")
            _unlink_private_file(key_path, label="retired file-custody root")
        try:
            _unlink_private_file(
                receipt_path,
                label="completed key-custody activation receipt",
            )
        except FileNotFoundError:
            if value.state == "verified":
                raise KeyUnavailable(
                    "key-custody activation receipt disappeared during retirement"
                ) from None
        return {"provider": active.provider, "state": "active"}

    def close(self) -> None:
        for client in tuple(self._custody_clients.values()):
            client.close()
        self._custody_clients.clear()
        self._derived_keys.clear()

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
        source_material = self._keys.get(source)
        key_path: Path | None = None
        descriptor_path: Path | None = None
        custody_client: CustodyClient | None = None
        target_material: bytes | CustodyDescriptor
        if isinstance(source_material, CustodyDescriptor):
            reference = f"evkc-{os.urandom(16).hex()}"
            descriptor = CustodyDescriptor(
                provider=source_material.provider,
                reference=reference,
                key_id=target,
                helper_path=source_material.helper_path,
                helper_sha256=source_material.helper_sha256,
                helper_cdhash=source_material.helper_cdhash,
                peer_cdhash=source_material.peer_cdhash,
                state="active",
            )
            custody_client = MacOSKeyCustodyClient(descriptor, self.profile_dir)
            try:
                if custody_client.import_root(key) != target:
                    raise KeyUnavailable("rotated opaque key identity changed")
                tag = custody_client.root_hmac(
                    self._custody_authentication_message(descriptor)
                ).hex()
                descriptor_path = self._custody_descriptor_path(reference)
                _secure_directory(descriptor_path.parent)
                _atomic_write_json(
                    descriptor_path,
                    descriptor.as_dict(tag_hex=tag),
                )
            except Exception:
                try:
                    custody_client.delete(confirm=True)
                except Exception:
                    pass
                custody_client.close()
                raise
            target_entry: dict[str, Any] = {
                "provider": descriptor.provider,
                "ref": descriptor.reference,
                "status": "active",
            }
            target_material = descriptor
        elif isinstance(source_material, bytes):
            relative_ref = f"keys/{target}.key"
            key_path = self.profile_dir / relative_ref
            _secure_directory(key_path.parent)
            _write_new_key(key_path, key)
            target_entry = {
                "ref": relative_ref,
                "status": "active",
            }
            target_material = key
        else:
            raise KeyUnavailable("active profile key is unavailable")
        manifest = copy.deepcopy(self._manifest)
        keys = manifest["keys"]
        if not isinstance(keys, dict):
            raise KeyUnavailable("profile key manifest is invalid")
        keys[source]["status"] = "decrypt-only"
        if RECORD_ENVELOPE_V3_FEATURE in self.features:
            target_entry["epoch"] = (
                max(
                    epoch for _key_id, epoch in self._key_epochs_from_manifest(manifest)
                )
                + 1
            )
        keys[target] = target_entry
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
            features=self.features,
            key_epochs=self._key_epochs_from_manifest(manifest),
        )
        try:
            _atomic_write_json(self.manifest_path, manifest)
        except Exception:
            if custody_client is not None:
                try:
                    custody_client.delete(confirm=True)
                except Exception:
                    pass
                custody_client.close()
                if descriptor_path is not None:
                    try:
                        _unlink_private_file(
                            descriptor_path,
                            label="unactivated key-custody descriptor",
                        )
                    except (KeyUnavailable, OSError):
                        pass
            elif key_path is not None:
                try:
                    _unlink_private_file(key_path, label="unactivated profile key")
                except OSError:
                    # Preserve the manifest failure; an orphan key is never activated.
                    pass
            raise
        self._manifest = manifest
        self._keys[target] = target_material
        if custody_client is not None:
            self._custody_clients[target] = custody_client
        self._derived_keys.clear()
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
        source_material = self._keys.get(source)
        key_path: Path | None = None
        descriptor_path: Path | None = None
        if isinstance(source_material, bytes):
            key_path = self.profile_dir / str(entry["ref"])
            _require_owner_file(key_path, "previous profile key")
        elif isinstance(source_material, CustodyDescriptor):
            descriptor_path = self._custody_descriptor_path(source_material.reference)
            _require_owner_file(descriptor_path, "previous key-custody descriptor")
            if self._client_for(source).probe().get("key_id") != source:
                raise KeyUnavailable("previous opaque key identity changed")
        else:
            raise KeyUnavailable("previous profile key is unavailable")
        del keys[source]
        manifest.pop("rotation", None)
        manifest["scope_binding"] = self._scope_binding_for_manifest(
            self.active_key_id,
            manifest,
        )
        _atomic_write_json(self.manifest_path, manifest)
        self._manifest = manifest
        self._keys.pop(source, None)
        self._derived_keys = {
            cache_key: value
            for cache_key, value in self._derived_keys.items()
            if cache_key[0] != source
        }
        if key_path is not None:
            _unlink_private_file(key_path, label="previous profile key")
        elif descriptor_path is not None:
            client = self._custody_clients.pop(source)
            try:
                client.delete(confirm=True)
            finally:
                client.close()
            _unlink_private_file(
                descriptor_path,
                label="previous key-custody descriptor",
            )
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
        raw = _read_private_file_bytes(
            self.manifest_path,
            label="profile key manifest",
            maximum=64 * 1024,
        )
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
            "features",
        }
        if set(decoded) - allowed or set(decoded) < allowed - {
            "features",
            "rotation",
        }:
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
        features = decoded.get("features", [])
        if (
            not isinstance(features, list)
            or len(features) > MAX_PROFILE_FEATURES
            or any(
                not isinstance(feature, str)
                or feature not in SUPPORTED_PROFILE_FEATURES
                for feature in features
            )
            or features != sorted(set(features))
        ):
            raise KeyUnavailable("profile key manifest features are invalid")
        v3_enabled = RECORD_ENVELOPE_V3_FEATURE in features
        active_count = 0
        for key_id, entry in keys.items():
            _validate_key_id(key_id)
            provider = entry.get("provider") if isinstance(entry, dict) else None
            opaque = provider in OPAQUE_KEY_CUSTODY
            expected_entry_fields = {"ref", "status"}
            if v3_enabled:
                expected_entry_fields.add("epoch")
            if opaque:
                expected_entry_fields.add("provider")
            if not isinstance(entry, dict) or set(entry) != expected_entry_fields:
                raise KeyUnavailable("profile key reference is invalid")
            reference = entry["ref"]
            status_value = entry["status"]
            if not isinstance(reference, str) or status_value not in {
                "active",
                "decrypt-only",
            }:
                raise KeyUnavailable("profile key reference is invalid")
            if opaque:
                if (
                    provider not in OPAQUE_KEY_CUSTODY
                    or _CUSTODY_REF_RE.fullmatch(reference) is None
                    or not v3_enabled
                ):
                    raise KeyUnavailable("opaque key-custody reference is invalid")
            elif provider is not None or _KEY_REF_RE.fullmatch(reference) is None:
                raise KeyUnavailable("profile key reference is invalid")
            if v3_enabled:
                epoch = entry["epoch"]
                if (
                    isinstance(epoch, bool)
                    or not isinstance(epoch, int)
                    or not 1 <= epoch <= 2**31 - 1
                ):
                    raise KeyUnavailable("profile key epoch is invalid")
            if status_value == "active":
                active_count += 1
        if active_count != 1 or keys[decoded["active_key_id"]]["status"] != "active":
            raise KeyUnavailable("profile active key state is invalid")
        if v3_enabled:
            self._key_epochs_from_manifest(decoded)
        return decoded

    def _load_referenced_keys(self) -> None:
        keys = self._manifest["keys"]
        for key_id, entry in keys.items():
            reference = str(entry["ref"])
            provider = entry.get("provider")
            if provider in OPAQUE_KEY_CUSTODY:
                descriptor_path = self._custody_descriptor_path(reference)
                raw = _read_private_file_bytes(
                    descriptor_path,
                    label="key-custody descriptor",
                    maximum=64 * 1024,
                )
                try:
                    descriptor, tag = CustodyDescriptor.from_json_bytes(raw)
                except ValueError as exc:
                    raise KeyUnavailable("key-custody descriptor is invalid") from exc
                if (
                    descriptor.reference != reference
                    or descriptor.provider != provider
                    or descriptor.key_id != key_id
                    or descriptor.state not in {"verified", "active"}
                ):
                    raise KeyUnavailable("key-custody descriptor binding is invalid")
                self._keys[key_id] = descriptor
                try:
                    expected = (
                        self._client_for(key_id)
                        .root_hmac(self._custody_authentication_message(descriptor))
                        .hex()
                    )
                except Exception as exc:
                    raise KeyUnavailable(
                        "key-custody descriptor is unavailable"
                    ) from exc
                if not hmac.compare_digest(expected, tag):
                    raise KeyUnavailable("key-custody descriptor authentication failed")
                continue
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
        expected = self._scope_binding_for_manifest(
            self.active_key_id,
            self._manifest,
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
    if object_type not in {
        "lifecycle-anchor",
        "memory-contract",
        "payload",
        "retrieval-vector",
    }:
        raise ValueError("encrypted object type is invalid")
    _validate_scope_id(scope_id)
    _validate_record_id(record_id)
    _validate_key_id(key_id)
    if schema_version not in SUPPORTED_RECORD_ENVELOPES:
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
        if self.schema_version not in SUPPORTED_RECORD_ENVELOPES:
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


@dataclass(frozen=True)
class ScopedProtectedBlob:
    """Small record-bound metadata object protected by the profile shield."""

    key_id: str
    scope_id: str
    record_id: str
    object_type: str
    nonce: bytes
    ciphertext: bytes
    schema_version: int = SCOPED_VECTOR_SCHEMA_VERSION
    algorithm: str = "AES-256-GCM-SCOPED"

    def __post_init__(self) -> None:
        _validate_key_id(self.key_id)
        _validate_scope_id(self.scope_id)
        _validate_record_id(self.record_id)
        if self.object_type != "memory-contract":
            raise ValueError("scoped protected blob object type is invalid")
        if self.schema_version not in SUPPORTED_RECORD_ENVELOPES:
            raise ValueError("scoped protected blob schema version is unsupported")
        if self.algorithm != "AES-256-GCM-SCOPED":
            raise ValueError("scoped protected blob algorithm is invalid")
        if not isinstance(self.nonce, bytes) or len(self.nonce) != AES_GCM_NONCE_BYTES:
            raise ValueError("scoped protected blob nonce is invalid")
        if (
            not isinstance(self.ciphertext, bytes)
            or not AES_GCM_TAG_BYTES
            < len(self.ciphertext)
            <= MAX_SCOPED_BLOB_PLAINTEXT_BYTES + AES_GCM_TAG_BYTES
        ):
            raise ValueError("scoped protected blob ciphertext size is invalid")

    def associated_data(self) -> bytes:
        return scoped_aad(
            object_type=self.object_type,
            scope_id=self.scope_id,
            record_id=self.record_id,
            schema_version=self.schema_version,
            key_id=self.key_id,
        )

    def to_json_bytes(self) -> bytes:
        encoded = json.dumps(
            {
                "algorithm": self.algorithm,
                "ciphertext_b64": base64.urlsafe_b64encode(self.ciphertext).decode(
                    "ascii"
                ),
                "key_id": self.key_id,
                "nonce_b64": base64.urlsafe_b64encode(self.nonce).decode("ascii"),
                "object_type": self.object_type,
                "record_id": self.record_id,
                "schema_version": self.schema_version,
                "scope_id": self.scope_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if len(encoded) > MAX_SCOPED_BLOB_JSON_BYTES:
            raise ValueError("scoped protected blob JSON exceeds the size limit")
        return encoded

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "ScopedProtectedBlob":
        if (
            not isinstance(payload, bytes)
            or not payload
            or len(payload) > MAX_SCOPED_BLOB_JSON_BYTES
        ):
            raise ValueError("scoped protected blob JSON has an invalid size")
        try:
            decoded = strict_json_loads(payload)
        except Exception as exc:
            raise ValueError("scoped protected blob JSON is invalid") from exc
        expected = {
            "algorithm",
            "ciphertext_b64",
            "key_id",
            "nonce_b64",
            "object_type",
            "record_id",
            "schema_version",
            "scope_id",
        }
        if not isinstance(decoded, dict) or set(decoded) != expected:
            raise ValueError("scoped protected blob fields are invalid")
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
            raise ValueError("scoped protected blob encoding is invalid") from exc
        return cls(
            algorithm=str(decoded["algorithm"]),
            ciphertext=ciphertext,
            key_id=str(decoded["key_id"]),
            nonce=nonce,
            object_type=str(decoded["object_type"]),
            record_id=str(decoded["record_id"]),
            schema_version=int(decoded["schema_version"]),
            scope_id=str(decoded["scope_id"]),
        )


class ScopedAesGcmShield:
    """Record-bound AES-GCM shield backed by a multi-key profile keyring."""

    algorithm = "AES-256-GCM-SCOPED"
    production_ready = False
    local_production_ready = False
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
        schema_version = self.keyring.record_envelope_write_version
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        protected = ScopedProtectedVector(
            key_id=key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            nonce=nonce,
            ciphertext=b"\0" * (vector.nbytes + AES_GCM_TAG_BYTES),
            shape=(int(vector.size),),
            schema_version=schema_version,
        )
        ciphertext = AESGCM(
            self.keyring.key_for_envelope(
                key_id,
                purpose=KEY_PURPOSE_VECTOR,
                envelope_version=schema_version,
            )
        ).encrypt(
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
            schema_version=schema_version,
        )

    def protect_blob_for_record(
        self,
        payload: bytes,
        record_id: str,
        *,
        object_type: str,
        key_id: str | None = None,
        schema_version: int | None = None,
    ) -> ScopedProtectedBlob:
        """Protect bounded semantic metadata under the same profile shield."""

        clean_id = _validate_record_id(record_id)
        if not isinstance(payload, bytes):
            raise TypeError("protected blob payload must be bytes")
        if not 0 < len(payload) <= MAX_SCOPED_BLOB_PLAINTEXT_BYTES:
            raise ValueError("protected blob payload has an invalid size")
        if object_type != "memory-contract":
            raise ValueError("protected blob object type is invalid")
        target_key_id = (
            self.keyring.active_key_id if key_id is None else _validate_key_id(key_id)
        )
        target_schema_version = (
            self.keyring.record_envelope_write_version
            if schema_version is None
            else schema_version
        )
        if target_schema_version not in SUPPORTED_RECORD_ENVELOPES:
            raise ValueError("target record-envelope version is unsupported")
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        placeholder = ScopedProtectedBlob(
            key_id=target_key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            object_type=object_type,
            nonce=nonce,
            ciphertext=b"\0" * (len(payload) + AES_GCM_TAG_BYTES),
            schema_version=target_schema_version,
        )
        ciphertext = AESGCM(
            self.keyring.key_for_envelope(
                target_key_id,
                purpose=KEY_PURPOSE_SEMANTIC_CONTRACT,
                envelope_version=target_schema_version,
            )
        ).encrypt(
            nonce,
            payload,
            placeholder.associated_data(),
        )
        return ScopedProtectedBlob(
            key_id=target_key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            object_type=object_type,
            nonce=nonce,
            ciphertext=ciphertext,
            schema_version=target_schema_version,
        )

    def reveal_blob(self, protected_blob: object) -> bytes:
        """Authenticate and reveal one bounded metadata object."""

        if not isinstance(protected_blob, ScopedProtectedBlob):
            raise TypeError("ScopedAesGcmShield expects a ScopedProtectedBlob")
        if protected_blob.scope_id != self.keyring.scope_id:
            raise ValueError("protected blob belongs to another authorization scope")
        try:
            plaintext = AESGCM(
                self.keyring.key_for_envelope(
                    protected_blob.key_id,
                    purpose=KEY_PURPOSE_SEMANTIC_CONTRACT,
                    envelope_version=protected_blob.schema_version,
                )
            ).decrypt(
                protected_blob.nonce,
                protected_blob.ciphertext,
                protected_blob.associated_data(),
            )
        except InvalidTag as exc:
            raise ValueError("protected blob authentication failed") from exc
        if not 0 < len(plaintext) <= MAX_SCOPED_BLOB_PLAINTEXT_BYTES:
            raise ValueError("protected blob plaintext size is invalid")
        return plaintext

    def reencrypt_blob(
        self,
        protected_blob: ScopedProtectedBlob,
        *,
        target_key_id: str,
        target_schema_version: int | None = None,
    ) -> ScopedProtectedBlob:
        """Rewrap metadata during the same resumable profile-key rotation."""

        target = _validate_key_id(target_key_id)
        target_version = (
            protected_blob.schema_version
            if target_schema_version is None
            else target_schema_version
        )
        if target_version not in SUPPORTED_RECORD_ENVELOPES:
            raise ValueError("target record-envelope version is unsupported")
        plaintext = bytearray(self.reveal_blob(protected_blob))
        try:
            nonce = os.urandom(AES_GCM_NONCE_BYTES)
            placeholder = ScopedProtectedBlob(
                key_id=target,
                scope_id=protected_blob.scope_id,
                record_id=protected_blob.record_id,
                object_type=protected_blob.object_type,
                nonce=nonce,
                ciphertext=b"\0" * (len(plaintext) + AES_GCM_TAG_BYTES),
                schema_version=target_version,
            )
            ciphertext = AESGCM(
                self.keyring.key_for_envelope(
                    target,
                    purpose=KEY_PURPOSE_SEMANTIC_CONTRACT,
                    envelope_version=target_version,
                )
            ).encrypt(
                nonce,
                bytes(plaintext),
                placeholder.associated_data(),
            )
            return ScopedProtectedBlob(
                key_id=target,
                scope_id=protected_blob.scope_id,
                record_id=protected_blob.record_id,
                object_type=protected_blob.object_type,
                nonce=nonce,
                ciphertext=ciphertext,
                schema_version=target_version,
            )
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

    def reveal(self, protected_anchor: object) -> NDArray[np.float64]:
        protected = self._validate(protected_anchor)
        plaintext = bytearray()
        try:
            plaintext = bytearray(
                AESGCM(
                    self.keyring.key_for_envelope(
                        protected.key_id,
                        purpose=KEY_PURPOSE_VECTOR,
                        envelope_version=protected.schema_version,
                    )
                ).decrypt(
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
        target_schema_version: int | None = None,
    ) -> ScopedProtectedVector:
        target = _validate_key_id(target_key_id)
        target_version = (
            protected_anchor.schema_version
            if target_schema_version is None
            else target_schema_version
        )
        if target_version not in SUPPORTED_RECORD_ENVELOPES:
            raise ValueError("target record-envelope version is unsupported")
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
                schema_version=target_version,
            )
            ciphertext = AESGCM(
                self.keyring.key_for_envelope(
                    target,
                    purpose=KEY_PURPOSE_VECTOR,
                    envelope_version=target_version,
                )
            ).encrypt(
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
                schema_version=target_version,
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
