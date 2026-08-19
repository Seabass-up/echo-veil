"""Owner-only serialized local RPC broker for Echo Veil agent adapters."""

from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import stat
import struct
import threading
import time
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from ._json import strict_json_loads

BROKER_SCHEMA = "echo-veil-local-broker-v1"
BROKER_TELEMETRY_SCHEMA = "echo-veil-broker-latency-v1"
MAX_BROKER_MESSAGE_BYTES = 1_048_576
MAX_UNIX_SOCKET_PATH_BYTES = 100
DEFAULT_BROKER_TIMEOUT_SECONDS = 120.0
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_CALLER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_ACTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

BrokerDispatcher = Callable[[str, Mapping[str, Any], str], dict[str, Any]]


class BrokerError(RuntimeError):
    """The local broker boundary is unavailable or returned invalid data."""


def default_broker_socket(profile_dir: str | os.PathLike[str]) -> Path:
    """Return the stable socket location inside one owner-only profile."""

    return Path(profile_dir).absolute() / "broker.sock"


def broker_authority_id(socket_path: str | os.PathLike[str]) -> str:
    """Return a path-free identifier for one configured broker endpoint."""

    path = os.fspath(Path(socket_path).expanduser().absolute()).encode("utf-8")
    return "sha256:" + hashlib.sha256(b"echo-veil-broker-path-v1\0" + path).hexdigest()


def validate_broker_socket(socket_path: str | os.PathLike[str]) -> Path:
    """Validate and return an existing owner-only broker socket."""

    path = _socket_path(socket_path)
    _verify_socket_file(path)
    return path


def _reject_symlink_components(path: Path) -> None:
    for candidate in reversed((path, *path.parents)):
        try:
            information = candidate.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(information.st_mode):
            raise BrokerError("broker paths must not contain symbolic links")


def _owner_only_directory(path: Path) -> None:
    _reject_symlink_components(path)
    try:
        information = path.stat()
    except OSError as exc:
        raise BrokerError("broker directory is unavailable") from exc
    if (
        not stat.S_ISDIR(information.st_mode)
        or information.st_mode & 0o077
        or (hasattr(os, "getuid") and information.st_uid != os.getuid())
    ):
        raise BrokerError("broker directory must be owner-only")


def _socket_path(value: str | os.PathLike[str]) -> Path:
    if not hasattr(socket, "AF_UNIX"):
        raise BrokerError("the local broker requires Unix-domain sockets")
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise BrokerError("broker socket path must be absolute")
    path = path.absolute()
    if len(os.fsencode(path)) > MAX_UNIX_SOCKET_PATH_BYTES:
        raise BrokerError("broker socket path exceeds the platform limit")
    _owner_only_directory(path.parent)
    return path


def _verify_socket_file(path: Path) -> os.stat_result:
    _reject_symlink_components(path)
    try:
        information = path.lstat()
    except OSError as exc:
        raise BrokerError("broker socket is unavailable") from exc
    if (
        not stat.S_ISSOCK(information.st_mode)
        or information.st_mode & 0o077
        or (hasattr(os, "getuid") and information.st_uid != os.getuid())
    ):
        raise BrokerError("broker socket is not owner-only")
    return information


def _read_frame(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(min(65_536, MAX_BROKER_MESSAGE_BYTES + 1 - total))
        if not chunk:
            break
        total += len(chunk)
        if total > MAX_BROKER_MESSAGE_BYTES:
            raise BrokerError("broker message exceeds its size limit")
        chunks.append(chunk)
        if b"\n" in chunk:
            break
    payload = b"".join(chunks)
    line, separator, remainder = payload.partition(b"\n")
    if not separator or remainder.strip():
        raise BrokerError("broker message framing is invalid")
    return line


def _write_frame(connection: socket.socket, value: Mapping[str, Any]) -> None:
    payload = (
        json.dumps(
            value,
            ensure_ascii=True,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("ascii")
        + b"\n"
    )
    if len(payload) > MAX_BROKER_MESSAGE_BYTES:
        raise BrokerError("broker response exceeds its size limit")
    connection.sendall(payload)


def _peer_is_current_user(connection: socket.socket) -> bool:
    if not hasattr(os, "getuid"):
        return True
    expected_uid = os.getuid()
    getpeereid = getattr(connection, "getpeereid", None)
    if callable(getpeereid):
        uid, _gid = getpeereid()
        return int(uid) == expected_uid
    peer_option = getattr(socket, "SO_PEERCRED", None)
    if peer_option is not None:
        raw = connection.getsockopt(
            socket.SOL_SOCKET, peer_option, struct.calcsize("3i")
        )
        _pid, uid, _gid = struct.unpack("3i", raw)
        return int(uid) == expected_uid
    # Socket mode 0600 and an owner-only parent remain the enforceable BSD
    # fallback when Python does not expose peer credentials on that platform.
    return True


class BrokerClient:
    """Bounded one-request client for an owner-only local broker."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        *,
        caller: str,
        timeout_seconds: float = DEFAULT_BROKER_TIMEOUT_SECONDS,
    ) -> None:
        if not isinstance(caller, str) or _CALLER_ID.fullmatch(caller) is None:
            raise ValueError("broker caller is invalid")
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.0 < float(timeout_seconds) <= DEFAULT_BROKER_TIMEOUT_SECONDS
        ):
            raise ValueError("broker timeout is invalid")
        self.socket_path = _socket_path(socket_path)
        self.caller = caller
        self.timeout_seconds = float(timeout_seconds)

    def call(
        self,
        action: str,
        arguments: Mapping[str, Any],
    ) -> dict[str, Any]:
        if not isinstance(action, str) or _ACTION.fullmatch(action) is None:
            raise ValueError("broker action is invalid")
        if not isinstance(arguments, Mapping):
            raise TypeError("broker arguments must be an object")
        request_id = os.urandom(16).hex()
        request = {
            "action": action,
            "arguments": dict(arguments),
            "caller": self.caller,
            "request_id": request_id,
            "schema": BROKER_SCHEMA,
        }
        _verify_socket_file(self.socket_path)
        started = time.perf_counter()
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                connection.settimeout(self.timeout_seconds)
                connection.connect(os.fspath(self.socket_path))
                _write_frame(connection, request)
                raw = _read_frame(connection)
        except (OSError, TimeoutError) as exc:
            raise BrokerError("Echo Veil broker is unavailable") from exc
        try:
            decoded = strict_json_loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise BrokerError("Echo Veil broker returned invalid JSON") from exc
        if not isinstance(decoded, Mapping):
            raise BrokerError("Echo Veil broker response is invalid")
        response = dict(decoded)
        if (
            response.get("schema") != BROKER_SCHEMA
            or response.get("request_id") != request_id
            or set(response)
            not in (
                {"ok", "request_id", "result", "schema", "telemetry"},
                {"error", "ok", "request_id", "schema", "telemetry"},
            )
        ):
            raise BrokerError("Echo Veil broker response binding is invalid")
        telemetry = response.get("telemetry")
        if not isinstance(telemetry, Mapping) or set(telemetry) != {
            "dispatch_ms",
            "payload_included",
            "schema",
        }:
            raise BrokerError("Echo Veil broker telemetry is invalid")
        dispatch_ms = telemetry.get("dispatch_ms")
        if (
            isinstance(dispatch_ms, bool)
            or not isinstance(dispatch_ms, (int, float))
            or not 0.0 <= float(dispatch_ms) <= self.timeout_seconds * 1_000.0
            or telemetry.get("payload_included") is not False
            or telemetry.get("schema") != BROKER_TELEMETRY_SCHEMA
        ):
            raise BrokerError("Echo Veil broker telemetry is invalid")
        if response.get("ok") is not True:
            if response.get("error") != "request_failed":
                raise BrokerError("Echo Veil broker error response is invalid")
            raise BrokerError("Echo Veil broker request failed")
        result = response.get("result")
        if not isinstance(result, Mapping):
            raise BrokerError("Echo Veil broker result is invalid")
        output = dict(result)
        output["broker_transport"] = {
            "dispatch_ms": round(float(dispatch_ms), 3),
            "payload_included": False,
            "round_trip_ms": round((time.perf_counter() - started) * 1_000.0, 3),
            "schema": BROKER_TELEMETRY_SCHEMA,
        }
        return output


class BrokerServer:
    """Serve one request at a time against a single long-lived memory adapter."""

    def __init__(
        self,
        socket_path: str | os.PathLike[str],
        dispatcher: BrokerDispatcher,
    ) -> None:
        self.socket_path = _socket_path(socket_path)
        self._dispatcher = dispatcher

    def serve_forever(
        self,
        *,
        stop_event: threading.Event | None = None,
        ready_event: threading.Event | None = None,
    ) -> None:
        stop = threading.Event() if stop_event is None else stop_event
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_identity: tuple[int, int] | None = None
        try:
            self._remove_stale_socket()
            previous_umask = os.umask(0o177)
            try:
                listener.bind(os.fspath(self.socket_path))
            finally:
                os.umask(previous_umask)
            os.chmod(self.socket_path, 0o600)
            information = _verify_socket_file(self.socket_path)
            bound_identity = (information.st_dev, information.st_ino)
            listener.listen(16)
            listener.settimeout(0.25)
            if ready_event is not None:
                ready_event.set()
            while not stop.is_set():
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                with connection:
                    connection.settimeout(DEFAULT_BROKER_TIMEOUT_SECONDS)
                    self._handle_connection(connection)
        finally:
            listener.close()
            self._unlink_bound_socket(bound_identity)

    def _handle_connection(self, connection: socket.socket) -> None:
        request_id = "0" * 32
        started = time.perf_counter()
        try:
            if not _peer_is_current_user(connection):
                raise BrokerError("broker peer is unauthorized")
            raw = _read_frame(connection)
            value = strict_json_loads(raw)
            if not isinstance(value, Mapping) or set(value) != {
                "action",
                "arguments",
                "caller",
                "request_id",
                "schema",
            }:
                raise BrokerError("broker request is invalid")
            request = dict(value)
            request_id_value = request.get("request_id")
            if (
                not isinstance(request_id_value, str)
                or _REQUEST_ID.fullmatch(request_id_value) is None
            ):
                raise BrokerError("broker request ID is invalid")
            request_id = request_id_value
            caller = request.get("caller")
            action = request.get("action")
            arguments = request.get("arguments")
            if (
                request.get("schema") != BROKER_SCHEMA
                or not isinstance(caller, str)
                or _CALLER_ID.fullmatch(caller) is None
                or not isinstance(action, str)
                or _ACTION.fullmatch(action) is None
                or not isinstance(arguments, Mapping)
            ):
                raise BrokerError("broker request binding is invalid")
            result = self._dispatcher(action, arguments, caller)
            if not isinstance(result, dict):
                raise BrokerError("broker dispatcher result is invalid")
            response: dict[str, Any] = {
                "ok": True,
                "request_id": request_id,
                "result": result,
                "schema": BROKER_SCHEMA,
            }
        except Exception:
            response = {
                "error": "request_failed",
                "ok": False,
                "request_id": request_id,
                "schema": BROKER_SCHEMA,
            }
        response["telemetry"] = {
            "dispatch_ms": round((time.perf_counter() - started) * 1_000.0, 3),
            "payload_included": False,
            "schema": BROKER_TELEMETRY_SCHEMA,
        }
        try:
            _write_frame(connection, response)
        except (BrokenPipeError, OSError):
            pass

    def _remove_stale_socket(self) -> None:
        try:
            information = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(information.st_mode):
            raise BrokerError("broker path already exists and is not a socket")
        if information.st_mode & 0o077 or (
            hasattr(os, "getuid") and information.st_uid != os.getuid()
        ):
            raise BrokerError("existing broker socket is unsafe")
        probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            probe.settimeout(0.1)
            probe.connect(os.fspath(self.socket_path))
        except (ConnectionRefusedError, FileNotFoundError, TimeoutError):
            pass
        except OSError as exc:
            raise BrokerError("existing broker socket cannot be verified") from exc
        else:
            raise BrokerError("an Echo Veil broker is already active")
        finally:
            probe.close()
        self._unlink_exact(information.st_dev, information.st_ino)

    def _unlink_bound_socket(self, identity: tuple[int, int] | None) -> None:
        if identity is None:
            return
        try:
            self._unlink_exact(*identity)
        except BrokerError:
            pass

    def _unlink_exact(self, device: int, inode: int) -> None:
        try:
            current = self.socket_path.lstat()
        except FileNotFoundError:
            return
        if (
            current.st_dev != device
            or current.st_ino != inode
            or not stat.S_ISSOCK(current.st_mode)
        ):
            raise BrokerError("broker socket changed during cleanup")
        descriptor = os.open(
            self.socket_path.parent,
            os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.unlink(self.socket_path.name, dir_fd=descriptor)
        finally:
            os.close(descriptor)
