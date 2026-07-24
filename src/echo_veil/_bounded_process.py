"""Shell-free child execution with bounded captured output and environment."""

from __future__ import annotations

import os
import math
import subprocess
import threading
from collections.abc import Sequence
from dataclasses import dataclass


MAX_PROCESS_INPUT_BYTES = 64 * 1024
_ENV_ALLOWLIST = frozenset(
    {
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "SYSTEMROOT",
        "TEMP",
        "TMP",
        "TMPDIR",
        "WINDIR",
    }
)


class ProcessOutputLimitError(RuntimeError):
    """A child produced more output than the caller permitted."""


@dataclass(frozen=True, slots=True)
class BoundedProcessResult:
    returncode: int
    stdout: bytes


def minimal_process_environment() -> dict[str, str]:
    """Keep runtime essentials while withholding unrelated host credentials."""

    return {name: value for name, value in os.environ.items() if name in _ENV_ALLOWLIST}


def run_bounded_process(
    argv: Sequence[str],
    *,
    input_bytes: bytes,
    timeout_seconds: float,
    maximum_output_bytes: int,
) -> BoundedProcessResult:
    """Run a fixed argv and stop reading before child output can exhaust memory."""

    if not argv or not all(isinstance(value, str) and value for value in argv):
        raise ValueError("child argv must contain non-empty strings")
    if not isinstance(input_bytes, bytes) or len(input_bytes) > MAX_PROCESS_INPUT_BYTES:
        raise ValueError("child input exceeds the safety limit")
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not math.isfinite(float(timeout_seconds))
        or not 0.0 < float(timeout_seconds) <= 300.0
    ):
        raise ValueError("child timeout must be within (0, 300] seconds")
    if (
        isinstance(maximum_output_bytes, bool)
        or not isinstance(maximum_output_bytes, int)
        or not 0 < maximum_output_bytes <= 16 * 1024 * 1024
    ):
        raise ValueError("maximum child output must be positive")

    process = subprocess.Popen(  # noqa: S603 -- fixed argv, no shell
        list(argv),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        shell=False,
        env=minimal_process_environment(),
    )
    child_stdin = process.stdin
    child_stdout = process.stdout
    if child_stdin is None or child_stdout is None:
        process.kill()
        raise RuntimeError("child process pipes are unavailable")

    output = bytearray()
    exceeded = threading.Event()
    reader_failed = threading.Event()
    writer_failed = threading.Event()

    def kill_if_running() -> None:
        try:
            if process.poll() is None:
                process.kill()
        except OSError:
            pass

    def read_stdout() -> None:
        try:
            while True:
                chunk = child_stdout.read(4096)
                if not chunk:
                    return
                if len(chunk) > maximum_output_bytes - len(output):
                    exceeded.set()
                    kill_if_running()
                    return
                output.extend(chunk)
        except (OSError, ValueError):
            if process.poll() is None:
                reader_failed.set()
                kill_if_running()

    def write_stdin() -> None:
        try:
            child_stdin.write(input_bytes)
            child_stdin.flush()
        except BrokenPipeError:
            pass
        except (OSError, ValueError):
            if process.poll() is None:
                writer_failed.set()
                kill_if_running()
        finally:
            try:
                child_stdin.close()
            except (OSError, ValueError):
                pass

    reader = threading.Thread(
        target=read_stdout,
        name="echo-veil-bounded-process-reader",
        daemon=True,
    )
    writer = threading.Thread(
        target=write_stdin,
        name="echo-veil-bounded-process-writer",
        daemon=True,
    )
    reader.start()
    writer.start()
    try:
        try:
            returncode = process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            kill_if_running()
            process.wait()
            raise
    finally:
        writer.join(timeout=1.0)
        reader.join(timeout=1.0)
        if writer.is_alive():
            try:
                child_stdin.close()
            except (OSError, ValueError):
                pass
            writer.join(timeout=1.0)
        if reader.is_alive():
            child_stdout.close()
            reader.join(timeout=1.0)

    if reader.is_alive() or reader_failed.is_set():
        raise RuntimeError("child process output could not be read safely")
    if writer.is_alive() or writer_failed.is_set():
        raise RuntimeError("child process input could not be written safely")
    if exceeded.is_set():
        raise ProcessOutputLimitError("child process output exceeded the safety limit")
    return BoundedProcessResult(returncode=returncode, stdout=bytes(output))
