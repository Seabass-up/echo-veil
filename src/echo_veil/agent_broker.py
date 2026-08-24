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
from collections import deque
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ._json import strict_json_loads

BROKER_SCHEMA = "echo-veil-local-broker-v1"
BROKER_TELEMETRY_SCHEMA = "echo-veil-broker-latency-v1"
MAX_BROKER_MESSAGE_BYTES = 1_048_576
MAX_UNIX_SOCKET_PATH_BYTES = 100
DEFAULT_BROKER_TIMEOUT_SECONDS = 120.0
DEFAULT_BROKER_QUEUE_DEPTH = 16
DEFAULT_BROKER_PER_CALLER_QUOTA = 4
MAX_BROKER_QUEUE_DEPTH = 256
MAX_BROKER_PER_CALLER_QUOTA = 64
_REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z")
_CALLER_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")
_ACTION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}\Z")

BrokerDispatcher = Callable[[str, Mapping[str, Any], str], dict[str, Any]]


class BrokerError(RuntimeError):
    """The local broker boundary is unavailable or returned invalid data."""


@dataclass(slots=True)
class _BrokerJob:
    request_id: str
    caller: str
    action: str
    arguments: Mapping[str, Any]
    accepted_at: float
    completed: threading.Event = field(default_factory=threading.Event)
    started: threading.Event = field(default_factory=threading.Event)
    response: dict[str, Any] | None = None
    cancelled: threading.Event = field(default_factory=threading.Event)


class _FairRequestQueue:
    """Bounded caller-round-robin queue used by the single writer worker."""

    def __init__(self, depth: int, per_caller_quota: int) -> None:
        self.depth = depth
        self.per_caller_quota = per_caller_quota
        self._condition = threading.Condition()
        self._queues: dict[str, deque[_BrokerJob]] = {}
        self._callers: deque[str] = deque()
        self._queued = 0
        self._closed = False

    def submit(self, job: _BrokerJob) -> str | None:
        with self._condition:
            if self._closed:
                return "broker_stopping"
            queue = self._queues.get(job.caller)
            caller_depth = 0 if queue is None else len(queue)
            if self._queued >= self.depth:
                return "saturated"
            if caller_depth >= self.per_caller_quota:
                return "caller_quota_exceeded"
            if queue is None:
                queue = deque()
                self._queues[job.caller] = queue
                self._callers.append(job.caller)
            queue.append(job)
            self._queued += 1
            self._condition.notify()
            return None

    def get(self, timeout: float = 0.25) -> _BrokerJob | None:
        deadline = time.monotonic() + timeout
        with self._condition:
            while not self._queued and not self._closed:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return None
                self._condition.wait(remaining)
            if not self._queued:
                return None
            caller = self._callers.popleft()
            queue = self._queues[caller]
            job = queue.popleft()
            self._queued -= 1
            if queue:
                self._callers.append(caller)
            else:
                del self._queues[caller]
            return job

    def close(self) -> list[_BrokerJob]:
        with self._condition:
            self._closed = True
            pending = [job for queue in self._queues.values() for job in queue]
            self._queues.clear()
            self._callers.clear()
            self._queued = 0
            self._condition.notify_all()
            return pending

    def cancel(self, job: _BrokerJob) -> bool:
        """Remove one still-queued job without touching an active dispatch."""

        with self._condition:
            queue = self._queues.get(job.caller)
            if queue is None:
                return False
            retained = deque(candidate for candidate in queue if candidate is not job)
            if len(retained) == len(queue):
                return False
            self._queued -= 1
            if retained:
                self._queues[job.caller] = retained
            else:
                del self._queues[job.caller]
                self._callers = deque(
                    caller for caller in self._callers if caller != job.caller
                )
            return True

    @property
    def queued(self) -> int:
        with self._condition:
            return self._queued


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
            error_code = response.get("error")
            if error_code not in {
                "broker_stopping",
                "caller_quota_exceeded",
                "deadline_exceeded",
                "request_failed",
                "saturated",
            }:
                raise BrokerError("Echo Veil broker error response is invalid")
            if error_code in {"saturated", "caller_quota_exceeded"}:
                raise BrokerError("Echo Veil broker is saturated")
            if error_code == "deadline_exceeded":
                raise BrokerError("Echo Veil broker request deadline expired")
            if error_code == "broker_stopping":
                raise BrokerError("Echo Veil broker is stopping")
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
        *,
        queue_depth: int = DEFAULT_BROKER_QUEUE_DEPTH,
        per_caller_quota: int = DEFAULT_BROKER_PER_CALLER_QUOTA,
        request_deadline_seconds: float = DEFAULT_BROKER_TIMEOUT_SECONDS,
    ) -> None:
        if (
            isinstance(queue_depth, bool)
            or not isinstance(queue_depth, int)
            or not 1 <= queue_depth <= MAX_BROKER_QUEUE_DEPTH
        ):
            raise ValueError("broker queue depth is invalid")
        if (
            isinstance(per_caller_quota, bool)
            or not isinstance(per_caller_quota, int)
            or not 1 <= per_caller_quota <= MAX_BROKER_PER_CALLER_QUOTA
            or per_caller_quota > queue_depth
        ):
            raise ValueError("broker per-caller quota is invalid")
        if (
            isinstance(request_deadline_seconds, bool)
            or not isinstance(request_deadline_seconds, (int, float))
            or not 0.1
            <= float(request_deadline_seconds)
            <= DEFAULT_BROKER_TIMEOUT_SECONDS
        ):
            raise ValueError("broker request deadline is invalid")
        self.socket_path = _socket_path(socket_path)
        self._dispatcher = dispatcher
        self._scheduler = _FairRequestQueue(queue_depth, per_caller_quota)
        self._request_deadline = float(request_deadline_seconds)
        # One active dispatch, ``queue_depth`` waiters, and one bounded slot to
        # parse and return a structured saturation response.
        self._connection_slots = threading.BoundedSemaphore(queue_depth + 2)
        self._metrics_lock = threading.Lock()
        self._queue_wait_samples: deque[float] = deque(maxlen=2_048)
        self._accepted = 0
        self._completed = 0
        self._rejected = 0
        self._deadline_rejected = 0

    def metrics(self) -> dict[str, object]:
        """Return payload-free broker saturation and queue timing telemetry."""

        with self._metrics_lock:
            samples = sorted(self._queue_wait_samples)
            if samples:
                index = max(0, ((95 * len(samples) + 99) // 100) - 1)
                p95 = round(samples[index], 3)
            else:
                p95 = 0.0
            return {
                "accepted": self._accepted,
                "completed": self._completed,
                "deadline_rejected": self._deadline_rejected,
                "payload_included": False,
                "queue_depth": self._scheduler.depth,
                "queue_wait_p95_ms": p95,
                "queued": self._scheduler.queued,
                "rejected": self._rejected,
                "schema": "echo-veil-broker-qos-v1",
            }

    def serve_forever(
        self,
        *,
        stop_event: threading.Event | None = None,
        ready_event: threading.Event | None = None,
    ) -> None:
        stop = threading.Event() if stop_event is None else stop_event
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        bound_identity: tuple[int, int] | None = None
        worker = threading.Thread(
            target=self._dispatch_loop,
            args=(stop,),
            name="echo-veil-broker-writer",
            daemon=True,
        )
        connections: list[threading.Thread] = []
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
            listener.listen(
                min(
                    self._scheduler.depth + 1,
                    getattr(socket, "SOMAXCONN", 128),
                )
            )
            listener.settimeout(0.25)
            worker.start()
            if ready_event is not None:
                ready_event.set()
            while not stop.is_set():
                try:
                    connection, _address = listener.accept()
                except TimeoutError:
                    continue
                if not self._connection_slots.acquire(blocking=False):
                    connection.close()
                    with self._metrics_lock:
                        self._rejected += 1
                    continue
                connections = [thread for thread in connections if thread.is_alive()]
                thread = threading.Thread(
                    target=self._connection_worker,
                    args=(connection,),
                    name="echo-veil-broker-connection",
                    daemon=True,
                )
                connections.append(thread)
                thread.start()
        finally:
            stop.set()
            for job in self._scheduler.close():
                job.response = self._error_response(
                    job.request_id,
                    "broker_stopping",
                    0.0,
                )
                job.completed.set()
            listener.close()
            worker.join(timeout=min(self._request_deadline, 5.0))
            for thread in connections:
                thread.join(timeout=0.1)
            self._unlink_bound_socket(bound_identity)

    def _connection_worker(self, connection: socket.socket) -> None:
        try:
            with connection:
                connection.settimeout(self._request_deadline)
                self._handle_connection(connection)
        finally:
            self._connection_slots.release()

    def _handle_connection(self, connection: socket.socket) -> None:
        request_id = "0" * 32
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
            job = _BrokerJob(
                request_id=request_id,
                caller=caller,
                action=action,
                arguments=dict(arguments),
                accepted_at=time.monotonic(),
            )
            rejection = self._scheduler.submit(job)
            if rejection is not None:
                with self._metrics_lock:
                    self._rejected += 1
                response = self._error_response(request_id, rejection, 0.0)
            elif not job.completed.wait(self._request_deadline):
                if self._scheduler.cancel(job):
                    job.cancelled.set()
                    with self._metrics_lock:
                        self._deadline_rejected += 1
                    response = self._error_response(
                        request_id,
                        "deadline_exceeded",
                        0.0,
                    )
                else:
                    # Python cannot safely interrupt a dispatcher that has begun,
                    # particularly a mutation. Preserve an unambiguous result by
                    # waiting for the bounded active operation instead of returning
                    # a deadline while it may still commit in the background.
                    job.completed.wait()
                    response = (
                        self._error_response(request_id, "request_failed", 0.0)
                        if job.response is None
                        else job.response
                    )
            elif job.response is None:
                response = self._error_response(request_id, "request_failed", 0.0)
            else:
                response = job.response
        except Exception:
            response = self._error_response(request_id, "request_failed", 0.0)
        try:
            _write_frame(connection, response)
        except (BrokenPipeError, OSError):
            # The caller may disconnect after its deadline; no retry is safe here.
            pass

    def _dispatch_loop(self, stop: threading.Event) -> None:
        while not stop.is_set():
            job = self._scheduler.get()
            if job is None:
                continue
            queue_wait_ms = (time.monotonic() - job.accepted_at) * 1_000.0
            with self._metrics_lock:
                self._accepted += 1
                self._queue_wait_samples.append(queue_wait_ms)
            if (
                job.cancelled.is_set()
                or queue_wait_ms > self._request_deadline * 1_000.0
            ):
                with self._metrics_lock:
                    self._deadline_rejected += 1
                job.response = self._error_response(
                    job.request_id,
                    "deadline_exceeded",
                    0.0,
                )
                job.completed.set()
                continue
            job.started.set()
            started = time.perf_counter()
            try:
                result = self._dispatcher(job.action, job.arguments, job.caller)
                if not isinstance(result, dict):
                    raise BrokerError("broker dispatcher result is invalid")
                dispatch_ms = (time.perf_counter() - started) * 1_000.0
                job.response = {
                    "ok": True,
                    "request_id": job.request_id,
                    "result": result,
                    "schema": BROKER_SCHEMA,
                    "telemetry": self._telemetry(dispatch_ms),
                }
                with self._metrics_lock:
                    self._completed += 1
            except Exception:
                dispatch_ms = (time.perf_counter() - started) * 1_000.0
                job.response = self._error_response(
                    job.request_id,
                    "request_failed",
                    dispatch_ms,
                )
            finally:
                job.completed.set()

    @staticmethod
    def _telemetry(dispatch_ms: float) -> dict[str, object]:
        return {
            "dispatch_ms": round(max(0.0, dispatch_ms), 3),
            "payload_included": False,
            "schema": BROKER_TELEMETRY_SCHEMA,
        }

    @classmethod
    def _error_response(
        cls,
        request_id: str,
        code: str,
        dispatch_ms: float,
    ) -> dict[str, Any]:
        return {
            "error": code,
            "ok": False,
            "request_id": request_id,
            "schema": BROKER_SCHEMA,
            "telemetry": cls._telemetry(dispatch_ms),
        }

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
            # Cleanup is best effort and must not unlink a replaced socket path.
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
