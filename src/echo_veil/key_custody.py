"""Opaque macOS root-key custody and its bounded native-helper protocol.

The memory and preflight protocols deliberately do not depend on this module.
It is an internal key-custody boundary used by record-envelope v3 profiles.
The native helper may return purpose-separated v3 subkeys, but it never returns
the profile root.  Version-2 root-key operations are intentionally unsupported
by opaque custody, so a profile must finish its v2-to-v3 migration first.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from ._json import strict_json_loads
from .record_envelope import (
    RECORD_ENVELOPE_KEY_PURPOSES,
    RECORD_ENVELOPE_V3,
    RECORD_ENVELOPE_V3_ALGORITHM,
)

FILE_CUSTODY_V1 = "file-v1"
MACOS_KEYCHAIN_V1 = "macos-keychain-v1"
MACOS_SECURE_ENCLAVE_V1 = "macos-secure-enclave-v1"
SUPPORTED_KEY_CUSTODY = frozenset(
    {FILE_CUSTODY_V1, MACOS_KEYCHAIN_V1, MACOS_SECURE_ENCLAVE_V1}
)
OPAQUE_KEY_CUSTODY = frozenset({MACOS_KEYCHAIN_V1, MACOS_SECURE_ENCLAVE_V1})

CUSTODY_DESCRIPTOR_SCHEMA = "echo-veil-key-custody-v1"
CUSTODY_REQUEST_SCHEMA = "echo-veil-key-custody-request-v1"
CUSTODY_RESPONSE_SCHEMA = "echo-veil-key-custody-response-v1"
MAX_CUSTODY_MESSAGE_BYTES = 1_048_576
DEFAULT_CUSTODY_TIMEOUT_SECONDS = 5.0

_HEX_40 = re.compile(r"[0-9a-f]{40}\Z")
_HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
_REFERENCE = re.compile(r"evkc-[0-9a-f]{32}\Z")
_KEY_ID = re.compile(r"ev-[0-9a-f]{16}\Z")
_SCOPE_ID = re.compile(r"scope-[0-9a-f]{32}\Z")
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")


class KeyCustodyUnavailable(RuntimeError):
    """The configured opaque key-custody boundary cannot be used safely."""


class KeyCustodyProtocolError(RuntimeError):
    """The native helper violated its exact bounded protocol."""


def _canonical_b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _decode_b64(value: object, *, label: str, maximum: int) -> bytes:
    if not isinstance(value, str) or not value or len(value) > (maximum * 2) + 8:
        raise KeyCustodyProtocolError(f"{label} is invalid")
    try:
        decoded = base64.b64decode(value, altchars=b"-_", validate=True)
    except (ValueError, TypeError) as exc:
        raise KeyCustodyProtocolError(f"{label} is invalid") from exc
    if len(decoded) > maximum or _canonical_b64(decoded) != value:
        raise KeyCustodyProtocolError(f"{label} is invalid")
    return decoded


def _require_hex(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class CustodyDescriptor:
    """Non-secret, root-authenticated description of one native custody item."""

    provider: str
    reference: str
    key_id: str
    helper_path: Path
    helper_sha256: str
    helper_cdhash: str
    peer_cdhash: str
    state: str = "prepared"
    schema: str = CUSTODY_DESCRIPTOR_SCHEMA

    def __post_init__(self) -> None:
        if self.schema != CUSTODY_DESCRIPTOR_SCHEMA:
            raise ValueError("key-custody descriptor schema is unsupported")
        if self.provider not in OPAQUE_KEY_CUSTODY:
            raise ValueError("key-custody provider is unsupported")
        _require_hex(self.reference, _REFERENCE, "key-custody reference")
        _require_hex(self.key_id, _KEY_ID, "key-custody key ID")
        absolute = Path(os.path.abspath(os.fspath(self.helper_path)))
        if absolute != self.helper_path or not absolute.is_absolute():
            raise ValueError("key-custody helper path must be absolute")
        _require_hex(self.helper_sha256, _HEX_64, "key-custody helper digest")
        _require_hex(self.helper_cdhash, _HEX_40, "key-custody helper code hash")
        _require_hex(self.peer_cdhash, _HEX_40, "key-custody peer code hash")
        if self.state not in {"prepared", "verified", "active"}:
            raise ValueError("key-custody migration state is invalid")

    def unsigned_dict(self) -> dict[str, object]:
        return {
            "helper_cdhash": self.helper_cdhash,
            "helper_path": os.fspath(self.helper_path),
            "helper_sha256": self.helper_sha256,
            "key_id": self.key_id,
            "peer_cdhash": self.peer_cdhash,
            "provider": self.provider,
            "reference": self.reference,
            "schema": self.schema,
            "state": self.state,
        }

    def authentication_message(self) -> bytes:
        return json.dumps(
            self.unsigned_dict(),
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    def as_dict(self, *, tag_hex: str) -> dict[str, object]:
        _require_hex(tag_hex, _HEX_64, "key-custody descriptor tag")
        return {**self.unsigned_dict(), "tag": tag_hex}

    @classmethod
    def from_dict(cls, value: object) -> tuple[CustodyDescriptor, str]:
        if not isinstance(value, dict):
            raise ValueError("key-custody descriptor must be an object")
        expected = {
            "helper_cdhash",
            "helper_path",
            "helper_sha256",
            "key_id",
            "peer_cdhash",
            "provider",
            "reference",
            "schema",
            "state",
            "tag",
        }
        if set(value) != expected:
            raise ValueError("key-custody descriptor fields are invalid")
        helper_path = value["helper_path"]
        if not isinstance(helper_path, str) or "\x00" in helper_path:
            raise ValueError("key-custody helper path is invalid")
        descriptor = cls(
            provider=str(value["provider"]),
            reference=str(value["reference"]),
            key_id=str(value["key_id"]),
            helper_path=Path(helper_path),
            helper_sha256=str(value["helper_sha256"]),
            helper_cdhash=str(value["helper_cdhash"]),
            peer_cdhash=str(value["peer_cdhash"]),
            state=str(value["state"]),
            schema=str(value["schema"]),
        )
        tag = _require_hex(value["tag"], _HEX_64, "key-custody descriptor tag")
        return descriptor, tag

    @classmethod
    def from_json_bytes(cls, raw: bytes) -> tuple[CustodyDescriptor, str]:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= 64 * 1024:
            raise ValueError("key-custody descriptor size is invalid")
        return cls.from_dict(strict_json_loads(raw))


class CustodyClient(Protocol):
    """Narrow operations exposed by an opaque root-custody implementation."""

    descriptor: CustodyDescriptor

    def import_root(self, root: bytes) -> str: ...

    def derive_v3_key(
        self,
        *,
        profile_scope: str,
        scope_id: str,
        key_epoch: int,
        purpose: str,
    ) -> bytes: ...

    def root_hmac(self, message: bytes) -> bytes: ...

    def probe(self) -> dict[str, str]: ...

    def export_portable(self, *, recovery_key: bytes, context: bytes) -> bytes: ...

    def import_portable(
        self,
        *,
        envelope: bytes,
        recovery_key: bytes,
        context: bytes,
    ) -> str: ...

    def generation(self) -> int: ...

    def advance_generation(self, *, expected: int, new: int) -> int: ...

    def delete(self, *, confirm: bool) -> None: ...

    def close(self) -> None: ...


def _sha256_file(path: Path, *, maximum: int = 32 * 1024 * 1024) -> str:
    digest = hashlib.sha256()
    total = 0
    flags = os.O_RDONLY | int(getattr(os, "O_CLOEXEC", 0))
    nofollow = getattr(os, "O_NOFOLLOW", None)
    if not isinstance(nofollow, int):
        raise KeyCustodyUnavailable("no-follow helper verification is unavailable")
    descriptor = os.open(path, flags | nofollow)
    try:
        information = os.fstat(descriptor)
        if (
            not stat.S_ISREG(information.st_mode)
            or int(information.st_nlink) != 1
            or int(information.st_uid) not in {0, os.getuid()}
            or stat.S_IMODE(information.st_mode) & 0o022
        ):
            raise KeyCustodyUnavailable("key-custody helper ownership is unsafe")
        while True:
            chunk = os.read(descriptor, 64 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if total > maximum:
                raise KeyCustodyUnavailable("key-custody helper exceeds size limit")
            digest.update(chunk)
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _codesign_information(path: Path) -> tuple[str, str]:
    if sys.platform != "darwin":
        raise KeyCustodyUnavailable("macOS key custody is unavailable on this host")
    environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
    verify = subprocess.run(
        ["/usr/bin/codesign", "--verify", "--strict", "--verbose=2", os.fspath(path)],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=DEFAULT_CUSTODY_TIMEOUT_SECONDS,
        env=environment,
    )
    if verify.returncode != 0:
        raise KeyCustodyUnavailable("key-custody helper signature is invalid")
    details = subprocess.run(
        ["/usr/bin/codesign", "-dv", "--verbose=4", os.fspath(path)],
        check=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=DEFAULT_CUSTODY_TIMEOUT_SECONDS,
        env=environment,
    )
    text = (details.stdout + details.stderr).decode("utf-8", errors="replace")
    match = re.search(r"(?:^|\n)CDHash=([0-9a-f]{40})(?:\n|$)", text)
    if details.returncode != 0 or match is None:
        raise KeyCustodyUnavailable("key-custody helper code identity is unavailable")
    identifier = re.search(r"(?:^|\n)Identifier=([^\n]{1,256})(?:\n|$)", text)
    return match.group(1), "" if identifier is None else identifier.group(1)


def executable_cdhash(path: Path | None = None) -> str:
    """Return the signed CDHash for a helper or the current Python peer."""

    target = Path(sys.executable).resolve() if path is None else path
    return _codesign_information(target)[0]


def helper_identity(path: Path) -> tuple[str, str]:
    """Return the pinned file digest and signed code hash for setup."""

    absolute = Path(os.path.abspath(os.fspath(path)))
    if absolute != path:
        raise ValueError("key-custody helper path must be absolute")
    return _sha256_file(absolute), _codesign_information(absolute)[0]


class MacOSKeyCustodyClient:
    """Bounded client for the signed Swift helper's owner-only Unix socket."""

    def __init__(
        self,
        descriptor: CustodyDescriptor,
        profile_dir: Path,
        *,
        timeout_seconds: float = DEFAULT_CUSTODY_TIMEOUT_SECONDS,
    ) -> None:
        if descriptor.provider not in OPAQUE_KEY_CUSTODY:
            raise ValueError("opaque custody client requires a native provider")
        if sys.platform != "darwin":
            raise KeyCustodyUnavailable("macOS key custody is unavailable on this host")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.1 <= float(timeout_seconds) <= 30.0
        ):
            raise ValueError("key-custody timeout is invalid")
        self.descriptor = descriptor
        self._timeout = float(timeout_seconds)
        self._socket: socket.socket | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._request_counter = 0

        helper_digest = _sha256_file(descriptor.helper_path)
        helper_cdhash, _identifier = _codesign_information(descriptor.helper_path)
        if helper_digest != descriptor.helper_sha256:
            raise KeyCustodyUnavailable("key-custody helper digest changed")
        if helper_cdhash != descriptor.helper_cdhash:
            raise KeyCustodyUnavailable("key-custody helper code identity changed")
        if executable_cdhash() != descriptor.peer_cdhash:
            raise KeyCustodyUnavailable("key-custody peer code identity changed")

        del profile_dir  # The helper never receives or logs the profile path.
        runtime_parent = Path("/private/tmp")
        parent_info = runtime_parent.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(parent_info.st_mode)
            or int(parent_info.st_uid) != 0
            or not bool(parent_info.st_mode & stat.S_ISVTX)
        ):
            raise KeyCustodyUnavailable("key-custody runtime parent is unsafe")
        runtime_dir: Path | None = None
        for _attempt in range(128):
            candidate = runtime_parent / (f"evkc-{os.getpid():x}-{os.urandom(8).hex()}")
            try:
                candidate.mkdir(mode=0o700)
            except FileExistsError:
                continue
            runtime_dir = candidate
            break
        if runtime_dir is None:
            raise KeyCustodyUnavailable("key-custody runtime allocation failed")
        self._runtime_dir = runtime_dir
        runtime_info = runtime_dir.stat(follow_symlinks=False)
        if (
            not stat.S_ISDIR(runtime_info.st_mode)
            or int(runtime_info.st_uid) != os.getuid()
            or stat.S_IMODE(runtime_info.st_mode) & 0o077
        ):
            raise KeyCustodyUnavailable("key-custody runtime directory is unsafe")
        socket_name = f"c-{os.getpid():x}-{os.urandom(6).hex()}.sock"
        self._socket_path = runtime_dir / socket_name
        if len(os.fsencode(self._socket_path)) >= 100:
            raise KeyCustodyUnavailable("key-custody socket path is too long")
        self._start()

    def _start(self) -> None:
        before = self.descriptor.helper_path.stat(follow_symlinks=False)
        environment = {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LANG": "C"}
        self._process = subprocess.Popen(
            [
                os.fspath(self.descriptor.helper_path),
                "serve",
                "--socket",
                os.fspath(self._socket_path),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            cwd="/",
            env=environment,
        )
        deadline = time.monotonic() + self._timeout
        connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        connection.settimeout(min(self._timeout, 1.0))
        while True:
            if self._process.poll() is not None:
                connection.close()
                raise KeyCustodyUnavailable("key-custody helper exited during startup")
            try:
                connection.connect(os.fspath(self._socket_path))
                break
            except (FileNotFoundError, ConnectionRefusedError):
                if time.monotonic() >= deadline:
                    connection.close()
                    self.close()
                    raise KeyCustodyUnavailable("key-custody helper startup timed out")
                time.sleep(0.01)
        connection.settimeout(self._timeout)
        after = self.descriptor.helper_path.stat(follow_symlinks=False)
        identity_before = (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_ctime_ns,
        )
        identity_after = (after.st_dev, after.st_ino, after.st_size, after.st_ctime_ns)
        if identity_before != identity_after:
            connection.close()
            self.close()
            raise KeyCustodyUnavailable("key-custody helper changed during startup")
        if _sha256_file(self.descriptor.helper_path) != self.descriptor.helper_sha256:
            connection.close()
            self.close()
            raise KeyCustodyUnavailable("key-custody helper changed during startup")
        socket_info = self._socket_path.lstat()
        if (
            not stat.S_ISSOCK(socket_info.st_mode)
            or int(socket_info.st_uid) != os.getuid()
            or stat.S_IMODE(socket_info.st_mode) & 0o077
        ):
            connection.close()
            self.close()
            raise KeyCustodyUnavailable("key-custody endpoint is unsafe")
        self._socket = connection

    def _read_exact(self, length: int) -> bytes:
        if self._socket is None:
            raise KeyCustodyUnavailable("key-custody helper is closed")
        chunks: list[bytes] = []
        remaining = length
        while remaining:
            chunk = self._socket.recv(remaining)
            if not chunk:
                raise KeyCustodyProtocolError("key-custody helper closed its response")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def _call(self, operation: str, arguments: dict[str, object]) -> dict[str, Any]:
        if self._socket is None:
            raise KeyCustodyUnavailable("key-custody helper is closed")
        self._request_counter += 1
        request_id = hashlib.sha256(
            os.urandom(32) + self._request_counter.to_bytes(8, "big")
        ).hexdigest()[:32]
        request = {
            "schema": CUSTODY_REQUEST_SCHEMA,
            "request_id": request_id,
            "operation": operation,
            "provider": self.descriptor.provider,
            "reference": self.descriptor.reference,
            **arguments,
        }
        encoded = json.dumps(
            request,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        if not 0 < len(encoded) <= MAX_CUSTODY_MESSAGE_BYTES:
            raise ValueError("key-custody request exceeds its safety bound")
        try:
            self._socket.sendall(struct.pack(">I", len(encoded)) + encoded)
            size = struct.unpack(">I", self._read_exact(4))[0]
            if not 0 < size <= MAX_CUSTODY_MESSAGE_BYTES:
                raise KeyCustodyProtocolError("key-custody response size is invalid")
            decoded = strict_json_loads(self._read_exact(size))
        except (OSError, TimeoutError) as exc:
            self.close()
            raise KeyCustodyUnavailable("key-custody helper operation failed") from exc
        if not isinstance(decoded, dict):
            raise KeyCustodyProtocolError("key-custody response must be an object")
        expected = {"schema", "request_id", "ok", "result", "error"}
        if set(decoded) != expected:
            raise KeyCustodyProtocolError("key-custody response fields are invalid")
        if (
            decoded["schema"] != CUSTODY_RESPONSE_SCHEMA
            or decoded["request_id"] != request_id
            or not isinstance(decoded["ok"], bool)
            or not isinstance(decoded["result"], dict)
            or (decoded["error"] is not None and not isinstance(decoded["error"], str))
        ):
            raise KeyCustodyProtocolError("key-custody response is invalid")
        if decoded["ok"] is not True:
            code = str(decoded["error"])
            if not re.fullmatch(r"EVKC-[A-Z0-9-]{1,48}", code):
                raise KeyCustodyProtocolError(
                    "key-custody helper returned an unsafe error"
                )
            raise KeyCustodyUnavailable(
                f"key-custody helper rejected the operation ({code})"
            )
        if decoded["error"] is not None:
            raise KeyCustodyProtocolError(
                "successful key-custody response has an error"
            )
        return dict(decoded["result"])

    def import_root(self, root: bytes) -> str:
        if not isinstance(root, bytes) or len(root) != 32:
            raise ValueError("profile root must contain exactly 32 bytes")
        result = self._call("import-root", {"root_b64": _canonical_b64(root)})
        if set(result) != {"key_id"}:
            raise KeyCustodyProtocolError("key import response fields are invalid")
        return _require_hex(result["key_id"], _KEY_ID, "key-custody key ID")

    def derive_v3_key(
        self,
        *,
        profile_scope: str,
        scope_id: str,
        key_epoch: int,
        purpose: str,
    ) -> bytes:
        if not isinstance(profile_scope, str) or not profile_scope:
            raise ValueError("profile scope is invalid")
        _require_hex(scope_id, _SCOPE_ID, "scope ID")
        if (
            isinstance(key_epoch, bool)
            or not isinstance(key_epoch, int)
            or not 1 <= key_epoch <= 2**31 - 1
        ):
            raise ValueError("key epoch is invalid")
        if purpose not in RECORD_ENVELOPE_KEY_PURPOSES:
            raise ValueError("record-envelope key purpose is unsupported")
        result = self._call(
            "derive-v3-key",
            {
                "algorithm": RECORD_ENVELOPE_V3_ALGORITHM,
                "envelope_version": RECORD_ENVELOPE_V3,
                "key_epoch": key_epoch,
                "profile_scope": profile_scope,
                "purpose": purpose,
                "scope_id": scope_id,
            },
        )
        if set(result) != {"key_b64"}:
            raise KeyCustodyProtocolError("key derivation response fields are invalid")
        key = _decode_b64(result["key_b64"], label="derived key", maximum=32)
        if len(key) != 32:
            raise KeyCustodyProtocolError("derived key length is invalid")
        return key

    def root_hmac(self, message: bytes) -> bytes:
        if not isinstance(message, bytes) or not 0 < len(message) <= 64 * 1024:
            raise ValueError("root authentication message is invalid")
        result = self._call("root-hmac", {"message_b64": _canonical_b64(message)})
        if set(result) != {"tag_b64"}:
            raise KeyCustodyProtocolError("root HMAC response fields are invalid")
        tag = _decode_b64(result["tag_b64"], label="root HMAC", maximum=32)
        if len(tag) != 32:
            raise KeyCustodyProtocolError("root HMAC length is invalid")
        return tag

    def probe(self) -> dict[str, str]:
        result = self._call("probe", {})
        if set(result) != {"key_id", "provider", "reference"}:
            raise KeyCustodyProtocolError("key-custody probe fields are invalid")
        key_id = _require_hex(result["key_id"], _KEY_ID, "key-custody key ID")
        if result["provider"] != self.descriptor.provider:
            raise KeyCustodyProtocolError("key-custody provider binding changed")
        if result["reference"] != self.descriptor.reference:
            raise KeyCustodyProtocolError("key-custody reference binding changed")
        return {
            "key_id": key_id,
            "provider": str(result["provider"]),
            "reference": str(result["reference"]),
        }

    @staticmethod
    def _portable_arguments(
        *,
        recovery_key: bytes,
        context: bytes,
    ) -> dict[str, object]:
        if not isinstance(recovery_key, bytes) or len(recovery_key) != 32:
            raise ValueError("portable recovery key must contain exactly 32 bytes")
        if not isinstance(context, bytes) or not 0 < len(context) <= 4_096:
            raise ValueError("portable recovery context is invalid")
        return {
            "context_b64": _canonical_b64(context),
            "recovery_key_b64": _canonical_b64(recovery_key),
        }

    def export_portable(self, *, recovery_key: bytes, context: bytes) -> bytes:
        arguments = self._portable_arguments(
            recovery_key=recovery_key,
            context=context,
        )
        result = self._call("export-portable", arguments)
        if set(result) != {"envelope_b64"}:
            raise KeyCustodyProtocolError("portable export response fields are invalid")
        envelope = _decode_b64(
            result["envelope_b64"],
            label="portable root envelope",
            maximum=256,
        )
        if len(envelope) < 48:
            raise KeyCustodyProtocolError("portable root envelope is invalid")
        return envelope

    def import_portable(
        self,
        *,
        envelope: bytes,
        recovery_key: bytes,
        context: bytes,
    ) -> str:
        if not isinstance(envelope, bytes) or not 48 <= len(envelope) <= 256:
            raise ValueError("portable root envelope is invalid")
        arguments = self._portable_arguments(
            recovery_key=recovery_key,
            context=context,
        )
        result = self._call(
            "import-portable",
            {**arguments, "envelope_b64": _canonical_b64(envelope)},
        )
        if set(result) != {"key_id"}:
            raise KeyCustodyProtocolError("portable import response fields are invalid")
        return _require_hex(result["key_id"], _KEY_ID, "key-custody key ID")

    def generation(self) -> int:
        result = self._call("generation", {})
        if set(result) != {"generation"}:
            raise KeyCustodyProtocolError("generation response fields are invalid")
        value = result["generation"]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise KeyCustodyProtocolError("key-custody generation is invalid")
        return value

    def advance_generation(self, *, expected: int, new: int) -> int:
        for value, label in ((expected, "expected"), (new, "new")):
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{label} generation is invalid")
        if new != expected + 1:
            raise ValueError("key-custody generation must advance by one")
        result = self._call(
            "advance-generation",
            {"expected_generation": expected, "new_generation": new},
        )
        if set(result) != {"generation"} or result["generation"] != new:
            raise KeyCustodyProtocolError("generation advance response is invalid")
        return new

    def delete(self, *, confirm: bool) -> None:
        if confirm is not True:
            raise ValueError("key-custody deletion requires confirm=true")
        result = self._call("delete", {"confirm": True})
        if result:
            raise KeyCustodyProtocolError("key-custody delete response is invalid")

    def close(self) -> None:
        connection, self._socket = self._socket, None
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        process, self._process = self._process, None
        if process is not None and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1.0)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1.0)
        try:
            self._socket_path.unlink(missing_ok=True)
        except (AttributeError, OSError):
            pass
        try:
            self._runtime_dir.rmdir()
        except (AttributeError, OSError):
            pass

    def __enter__(self) -> MacOSKeyCustodyClient:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def __del__(self) -> None:  # pragma: no cover - defensive finalizer only
        self.close()


__all__ = [
    "CUSTODY_DESCRIPTOR_SCHEMA",
    "FILE_CUSTODY_V1",
    "MACOS_KEYCHAIN_V1",
    "MACOS_SECURE_ENCLAVE_V1",
    "OPAQUE_KEY_CUSTODY",
    "SUPPORTED_KEY_CUSTODY",
    "CustodyClient",
    "CustodyDescriptor",
    "KeyCustodyProtocolError",
    "KeyCustodyUnavailable",
    "MacOSKeyCustodyClient",
    "executable_cdhash",
    "helper_identity",
]
