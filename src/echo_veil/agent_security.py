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
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
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
MAX_SCOPED_BLOB_PLAINTEXT_BYTES = 1024
MAX_SCOPED_BLOB_JSON_BYTES = 2048
MAX_SCOPE_CHARS = 256
MAX_PROFILE_FEATURES = 16
SUPPORTED_PROFILE_FEATURES = frozenset({"shielded-four-layer-v1"})
KEY_ID_PREFIX = "ev-"
_KEY_ID_RE = re.compile(r"ev-[0-9a-f]{16}\Z")
_RECORD_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SCOPE_ID_RE = re.compile(r"scope-[0-9a-f]{32}\Z")
_KEY_REF_RE = re.compile(r"(?:agent\.key|keys/ev-[0-9a-f]{16}\.key)\Z")


class KeyUnavailable(RuntimeError):
    """A referenced profile key is missing or cannot be used safely."""


@dataclass(frozen=True)
class _WindowsFileState:
    """Identity and ACL material pinned to one native Windows file handle."""

    identity: tuple[int, ...]
    owner: bytes
    dacl: bytes


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


def _scope_binding(
    key: bytes,
    scope: str,
    scope_id: str,
    *,
    features: tuple[str, ...] = (),
) -> str:
    digest = hmac.new(key, digestmod=hashlib.sha256)
    digest.update(b"echo-veil-scope-binding-v1\0")
    digest.update(scope_id.encode("ascii"))
    digest.update(b"\0")
    digest.update(scope.encode("utf-8"))
    for feature in features:
        digest.update(b"\0feature\0")
        digest.update(feature.encode("ascii"))
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


def _secure_directory(path: Path) -> Path:
    _reject_symlink_components(path)
    if os.name == "nt":
        return _windows_ensure_private_directory(path)
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
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise KeyUnavailable(f"{label} permissions are too broad")


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
    _require_owner_file(path, "profile key")
    descriptor = os.open(path, _binary_noninheritable_read_flags())
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
    if os.name == "nt":
        _atomic_write_json_windows(path, encoded)
        return
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
            # A successful replace already moved the temporary file.
            pass


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
            except OSError:
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

    @property
    def features(self) -> tuple[str, ...]:
        raw = self._manifest.get("features", [])
        if not isinstance(raw, list):
            raise KeyUnavailable("profile key manifest features are invalid")
        return tuple(str(feature) for feature in raw)

    def has_feature(self, feature: str) -> bool:
        if feature not in SUPPORTED_PROFILE_FEATURES:
            raise ValueError("profile feature is unsupported")
        return feature in self.features

    def enable_feature(self, feature: str) -> None:
        if feature not in SUPPORTED_PROFILE_FEATURES:
            raise ValueError("profile feature is unsupported")
        if feature in self.features:
            return
        features = tuple(sorted((*self.features, feature)))
        manifest = copy.deepcopy(self._manifest)
        manifest["features"] = list(features)
        manifest["scope_binding"] = _scope_binding(
            self.active_key(),
            self.scope,
            self.scope_id,
            features=features,
        )
        _atomic_write_json(self.manifest_path, manifest)
        self._manifest = manifest

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
            features=self.features,
        )
        try:
            _atomic_write_json(self.manifest_path, manifest)
        except Exception:
            try:
                key_path.unlink()
            except OSError:
                # Preserve the manifest failure; an orphan key is never activated.
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
            features=self.features,
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
        if self.schema_version != SCOPED_VECTOR_SCHEMA_VERSION:
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

    def protect_blob_for_record(
        self,
        payload: bytes,
        record_id: str,
        *,
        object_type: str,
    ) -> ScopedProtectedBlob:
        """Protect bounded semantic metadata under the same profile shield."""

        clean_id = _validate_record_id(record_id)
        if not isinstance(payload, bytes):
            raise TypeError("protected blob payload must be bytes")
        if not 0 < len(payload) <= MAX_SCOPED_BLOB_PLAINTEXT_BYTES:
            raise ValueError("protected blob payload has an invalid size")
        if object_type != "memory-contract":
            raise ValueError("protected blob object type is invalid")
        key_id = self.keyring.active_key_id
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        placeholder = ScopedProtectedBlob(
            key_id=key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            object_type=object_type,
            nonce=nonce,
            ciphertext=b"\0" * (len(payload) + AES_GCM_TAG_BYTES),
        )
        ciphertext = AESGCM(self.keyring.key(key_id)).encrypt(
            nonce,
            payload,
            placeholder.associated_data(),
        )
        return ScopedProtectedBlob(
            key_id=key_id,
            scope_id=self.keyring.scope_id,
            record_id=clean_id,
            object_type=object_type,
            nonce=nonce,
            ciphertext=ciphertext,
        )

    def reveal_blob(self, protected_blob: object) -> bytes:
        """Authenticate and reveal one bounded metadata object."""

        if not isinstance(protected_blob, ScopedProtectedBlob):
            raise TypeError("ScopedAesGcmShield expects a ScopedProtectedBlob")
        if protected_blob.scope_id != self.keyring.scope_id:
            raise ValueError("protected blob belongs to another authorization scope")
        try:
            plaintext = AESGCM(self.keyring.key(protected_blob.key_id)).decrypt(
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
    ) -> ScopedProtectedBlob:
        """Rewrap metadata during the same resumable profile-key rotation."""

        target = _validate_key_id(target_key_id)
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
            )
            ciphertext = AESGCM(self.keyring.key(target)).encrypt(
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
            )
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

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
