#!/usr/bin/env python3
"""Verify one installed OpenClaw/Echo Veil singular-memory deployment.

The gate is payload-silent. It reads only bounded configuration and runtime
metadata, verifies the managed JavaScript archive plus the Python wheel, and
emits no local paths, profile keys, memory payloads, or provider credentials.
It qualifies local staging by default; production readiness remains a separate
explicit gate.
"""

from __future__ import annotations

import argparse
import configparser
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import urllib.parse
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCK = ROOT / "integrations" / "openclaw" / "deployment-lock.json"
MAX_JSON_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 2_000
MAX_INSTALLED_SOURCE_BYTES = 64 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30.0
DOCTOR_TIMEOUT_SECONDS = 120.0
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
PROFILE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

REQUIRED_TOOLS = frozenset(
    {
        "echo_veil_context",
        "echo_veil_doctor",
        "echo_veil_forget",
        "echo_veil_list",
        "echo_veil_promote",
        "echo_veil_recall",
        "echo_veil_refresh_live",
        "echo_veil_reindex",
        "echo_veil_remember",
    }
)
REQUIRED_HOOKS = frozenset(
    {
        "before_agent_reply",
        "before_agent_run",
        "before_prompt_build",
    }
)


class DeploymentError(RuntimeError):
    """The installed deployment is malformed, unsafe, or unverifiable."""


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise DeploymentError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_json_constant(value: str) -> None:
    raise DeploymentError(f"invalid JSON constant: {value}")


def _bounded_json(raw: bytes, label: str) -> Any:
    if len(raw) > MAX_JSON_BYTES:
        raise DeploymentError(f"{label} exceeds the output limit")
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_pairs_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DeploymentError(f"{label} is not valid JSON") from exc


def _mapping(value: object, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise DeploymentError(f"{label} must be an object")
    return value


def _string(value: object, label: str, *, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or any(ord(character) < 0x20 for character in value)
    ):
        raise DeploymentError(f"{label} must be a bounded non-empty string")
    return value


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _read_bounded(path: Path, *, maximum: int, label: str) -> bytes:
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise DeploymentError(f"{label} is unavailable") from exc
    if size < 1 or size > maximum:
        raise DeploymentError(f"{label} has an invalid size")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DeploymentError(f"{label} cannot be read") from exc


def _regular_path(
    value: str,
    label: str,
    *,
    allow_final_symlink: bool = False,
    owner_only: bool = False,
) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise DeploymentError(f"{label} must be absolute")
    current = Path(path.anchor)
    components = path.parts[1:]
    for index, component in enumerate(components):
        current /= component
        if current.is_symlink() and not (
            allow_final_symlink and index == len(components) - 1
        ):
            raise DeploymentError(f"{label} contains a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DeploymentError(f"{label} is unavailable") from exc
    if not resolved.is_file():
        raise DeploymentError(f"{label} must be a regular file")
    mode = stat.S_IMODE(resolved.stat().st_mode)
    if mode & 0o022:
        raise DeploymentError(f"{label} must not be group- or world-writable")
    if owner_only and mode & 0o077:
        raise DeploymentError(f"{label} must be owner-only")
    return resolved


def _directory_path(value: str, label: str) -> Path:
    path = Path(value)
    if not path.is_absolute():
        raise DeploymentError(f"{label} must be an absolute real directory")
    current = Path(path.anchor)
    for component in path.parts[1:]:
        current /= component
        if current.is_symlink():
            raise DeploymentError(f"{label} contains a symbolic link")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DeploymentError(f"{label} is unavailable") from exc
    if not resolved.is_dir():
        raise DeploymentError(f"{label} must be a directory")
    if stat.S_IMODE(resolved.stat().st_mode) & 0o022:
        raise DeploymentError(f"{label} must not be group- or world-writable")
    return resolved


def load_lock(path: Path) -> dict[str, Any]:
    """Load and strictly validate the public artifact lock."""

    raw = _bounded_json(
        _read_bounded(path, maximum=64 * 1024, label="deployment lock"),
        "deployment lock",
    )
    value = _mapping(raw, "deployment lock")
    if set(value) != {
        "schema_version",
        "source_date_epoch",
        "tested_on",
        "openclaw_version",
        "plugin",
        "python",
        "profile",
    }:
        raise DeploymentError("deployment lock has an invalid field set")
    if value.get("schema_version") != 1:
        raise DeploymentError("deployment lock schema is unsupported")
    source_date_epoch = value.get("source_date_epoch")
    if (
        not isinstance(source_date_epoch, int)
        or isinstance(source_date_epoch, bool)
        or source_date_epoch < 1
    ):
        raise DeploymentError("source_date_epoch must be a positive integer")
    tested_on = _string(value.get("tested_on"), "tested_on", maximum=10)
    if re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", tested_on) is None:
        raise DeploymentError("tested_on must be YYYY-MM-DD")

    plugin = _mapping(value.get("plugin"), "plugin lock")
    if set(plugin) != {"id", "version", "archive_sha256", "entrypoint_sha256"}:
        raise DeploymentError("plugin lock has an invalid field set")
    python = _mapping(value.get("python"), "Python lock")
    if set(python) != {
        "distribution",
        "version",
        "wheel_sha256",
        "console_body_sha256",
    }:
        raise DeploymentError("Python lock has an invalid field set")
    profile = _mapping(value.get("profile"), "profile lock")
    if set(profile) != {
        "id",
        "scope",
        "embedding_backend",
        "embedding_model",
        "embedding_dimension",
    }:
        raise DeploymentError("profile lock has an invalid field set")

    plugin_id = _string(plugin.get("id"), "plugin.id", maximum=64)
    plugin_version = _string(plugin.get("version"), "plugin.version", maximum=80)
    archive_sha256 = _string(
        plugin.get("archive_sha256"), "plugin.archive_sha256", maximum=64
    )
    entrypoint_sha256 = _string(
        plugin.get("entrypoint_sha256"),
        "plugin.entrypoint_sha256",
        maximum=64,
    )
    distribution = _string(
        python.get("distribution"), "python.distribution", maximum=128
    )
    python_version = _string(python.get("version"), "python.version", maximum=80)
    wheel_sha256 = _string(
        python.get("wheel_sha256"), "python.wheel_sha256", maximum=64
    )
    console_body_sha256 = _string(
        python.get("console_body_sha256"),
        "python.console_body_sha256",
        maximum=64,
    )
    for label, digest in (
        ("plugin.archive_sha256", archive_sha256),
        ("plugin.entrypoint_sha256", entrypoint_sha256),
        ("python.wheel_sha256", wheel_sha256),
        ("python.console_body_sha256", console_body_sha256),
    ):
        if HEX_SHA256.fullmatch(digest) is None:
            raise DeploymentError(f"{label} is not SHA-256")

    profile_id = _string(profile.get("id"), "profile.id", maximum=128)
    if PROFILE_ID.fullmatch(profile_id) is None:
        raise DeploymentError("profile.id is invalid")
    dimension = profile.get("embedding_dimension")
    if not isinstance(dimension, int) or isinstance(dimension, bool) or dimension < 1:
        raise DeploymentError("profile.embedding_dimension must be positive")

    return {
        "schema_version": 1,
        "source_date_epoch": source_date_epoch,
        "tested_on": tested_on,
        "openclaw_version": _string(
            value.get("openclaw_version"), "openclaw_version", maximum=80
        ),
        "plugin": {
            "id": plugin_id,
            "version": plugin_version,
            "archive_sha256": archive_sha256,
            "entrypoint_sha256": entrypoint_sha256,
        },
        "python": {
            "distribution": distribution,
            "version": python_version,
            "wheel_sha256": wheel_sha256,
            "console_body_sha256": console_body_sha256,
        },
        "profile": {
            "id": profile_id,
            "scope": _string(profile.get("scope"), "profile.scope", maximum=128),
            "embedding_backend": _string(
                profile.get("embedding_backend"),
                "profile.embedding_backend",
                maximum=32,
            ),
            "embedding_model": _string(
                profile.get("embedding_model"),
                "profile.embedding_model",
                maximum=128,
            ),
            "embedding_dimension": dimension,
        },
    }


def _safe_environment() -> dict[str, str]:
    allowed = (
        "HOME",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "PATH",
        "TMPDIR",
        "USERPROFILE",
    )
    return {name: os.environ[name] for name in allowed if name in os.environ}


class OpenClawClient:
    """Run a fixed set of bounded, read-only OpenClaw inspection commands."""

    def __init__(self) -> None:
        executable = shutil.which("openclaw")
        if executable is None:
            raise DeploymentError("OpenClaw executable is unavailable")
        self.executable = str(Path(executable).resolve(strict=True))

    def _run(
        self,
        arguments: Sequence[str],
        *,
        allow_missing: bool = False,
        timeout: float = COMMAND_TIMEOUT_SECONDS,
    ) -> bytes | None:
        try:
            completed = subprocess.run(  # noqa: S603 -- fixed read-only CLI
                [self.executable, *arguments],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=_safe_environment(),
                shell=False,
                check=False,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise DeploymentError("OpenClaw inspection command failed") from exc
        if completed.returncode != 0:
            if allow_missing:
                return None
            raise DeploymentError("OpenClaw inspection command was rejected")
        if len(completed.stdout) > MAX_JSON_BYTES:
            raise DeploymentError("OpenClaw inspection output is oversized")
        return completed.stdout

    def json(self, arguments: Sequence[str], label: str) -> Any:
        raw = self._run(arguments)
        assert raw is not None
        return _bounded_json(raw, label)

    def config(self, field: str, *, allow_missing: bool = False) -> Any:
        raw = self._run(
            ("config", "get", field, "--json"),
            allow_missing=allow_missing,
        )
        if raw is None:
            return None
        return _bounded_json(raw, f"OpenClaw config field {field}")


def verify_plugin_artifact(
    inspection: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> dict[str, object]:
    """Bind the installed plugin entry point to one immutable npm archive."""

    plugin = _mapping(inspection.get("plugin"), "plugin inspection")
    install = _mapping(inspection.get("install"), "plugin installation")
    plugin_lock = _mapping(lock.get("plugin"), "plugin lock")
    if install.get("source") != "archive":
        raise DeploymentError("Echo Veil plugin is not archive-installed")
    archive = _regular_path(
        _string(install.get("sourcePath"), "plugin archive path", maximum=4_096),
        "plugin archive",
        owner_only=True,
    )
    root = _directory_path(
        _string(plugin.get("rootDir"), "plugin root", maximum=4_096),
        "plugin root",
    )
    entrypoint = _regular_path(
        _string(plugin.get("source"), "plugin source", maximum=4_096),
        "plugin entrypoint",
    )
    try:
        relative_entrypoint = entrypoint.relative_to(root).as_posix()
    except ValueError as exc:
        raise DeploymentError("plugin entrypoint escapes its managed root") from exc
    if relative_entrypoint != "dist/index.js":
        raise DeploymentError("plugin entrypoint is not the managed distribution")

    archive_bytes = _read_bounded(
        archive,
        maximum=MAX_ARTIFACT_BYTES,
        label="plugin archive",
    )
    archive_digest = _sha256_bytes(archive_bytes)
    if archive_digest != plugin_lock.get("archive_sha256"):
        raise DeploymentError("plugin archive hash does not match the lock")
    entrypoint_bytes = _read_bounded(
        entrypoint,
        maximum=MAX_INSTALLED_SOURCE_BYTES,
        label="plugin entrypoint",
    )
    entrypoint_digest = _sha256_bytes(entrypoint_bytes)
    if entrypoint_digest != plugin_lock.get("entrypoint_sha256"):
        raise DeploymentError(
            "installed plugin entrypoint hash does not match the lock"
        )

    archive_entrypoints: list[bytes] = []
    total_bytes = 0
    try:
        with tarfile.open(archive, "r:gz") as bundle:
            members = bundle.getmembers()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise DeploymentError("plugin archive has too many members")
            for member in members:
                if member.issym() or member.islnk():
                    raise DeploymentError("plugin archive contains a link")
                pure = Path(member.name)
                if pure.is_absolute() or ".." in pure.parts:
                    raise DeploymentError("plugin archive contains an unsafe path")
                if member.isfile():
                    total_bytes += member.size
                    if total_bytes > MAX_ARTIFACT_BYTES:
                        raise DeploymentError("plugin archive expands past its limit")
                if member.isfile() and member.name == "package/dist/index.js":
                    extracted = bundle.extractfile(member)
                    if extracted is None:
                        raise DeploymentError("plugin archive entrypoint is unreadable")
                    archive_entrypoints.append(extracted.read())
    except (OSError, tarfile.TarError) as exc:
        raise DeploymentError("plugin archive is invalid") from exc
    if len(archive_entrypoints) != 1:
        raise DeploymentError("plugin archive must contain one entrypoint")
    if _sha256_bytes(archive_entrypoints[0]) != entrypoint_digest:
        raise DeploymentError("installed plugin differs from its archive")
    return {
        "version": plugin.get("version"),
        "archive_sha256": archive_digest,
        "entrypoint_sha256": entrypoint_digest,
        "artifact_bound": True,
    }


def _find_site_packages(venv: Path) -> Path:
    candidates = sorted(
        path
        for path in (venv / "lib").glob("python*/site-packages")
        if path.is_dir() and not path.is_symlink()
    )
    if len(candidates) != 1:
        raise DeploymentError("Python environment has ambiguous site-packages")
    return candidates[0].resolve(strict=True)


def _wheel_path(direct_url: Mapping[str, Any], expected_hash: str) -> Path:
    if set(direct_url) - {"url", "archive_info", "subdirectory"}:
        raise DeploymentError("PEP 610 receipt has unexpected fields")
    parsed = urllib.parse.urlparse(
        _string(direct_url.get("url"), "PEP 610 URL", maximum=8_192)
    )
    if parsed.scheme != "file" or parsed.netloc not in {"", "localhost"}:
        raise DeploymentError("PEP 610 receipt is not a local wheel")
    archive_info = _mapping(direct_url.get("archive_info"), "PEP 610 archive info")
    if archive_info.get("hash") != f"sha256={expected_hash}":
        raise DeploymentError("PEP 610 archive hash does not match the lock")
    return _regular_path(
        urllib.parse.unquote(parsed.path),
        "Python wheel",
        owner_only=True,
    )


def verify_python_artifact(
    executable_value: str,
    lock: Mapping[str, Any],
) -> dict[str, object]:
    """Verify the configured console script and installed package from its wheel."""

    python_lock = _mapping(lock.get("python"), "Python lock")
    executable = _regular_path(
        executable_value,
        "Echo Veil executable",
        allow_final_symlink=True,
    )
    script = _read_bounded(
        executable,
        maximum=64 * 1024,
        label="Echo Veil console script",
    )
    try:
        shebang, body = script.split(b"\n", 1)
    except ValueError as exc:
        raise DeploymentError("Echo Veil console script has no body") from exc
    if not shebang.startswith(b"#!/") or b"\x00" in shebang:
        raise DeploymentError("Echo Veil console script has an invalid shebang")
    if _sha256_bytes(body) != python_lock.get("console_body_sha256"):
        raise DeploymentError("Echo Veil console script body does not match the lock")
    try:
        interpreter_value = shebang[2:].decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DeploymentError("Echo Veil console script shebang is invalid") from exc
    _regular_path(
        interpreter_value,
        "Echo Veil Python interpreter",
        allow_final_symlink=True,
    )
    venv = Path(interpreter_value).parent.parent
    if executable.parent != (venv / "bin").resolve(strict=True):
        raise DeploymentError(
            "Echo Veil executable and interpreter environments differ"
        )
    site_packages = _find_site_packages(venv)
    dist_infos = sorted(site_packages.glob("echo_veil-*.dist-info"))
    if len(dist_infos) != 1 or dist_infos[0].is_symlink():
        raise DeploymentError("Echo Veil distribution metadata is ambiguous")
    dist_info = dist_infos[0].resolve(strict=True)
    metadata = BytesParser().parsebytes(
        _read_bounded(
            dist_info / "METADATA",
            maximum=512 * 1024,
            label="Python package metadata",
        )
    )
    if metadata.get("Name") != python_lock.get("distribution"):
        raise DeploymentError("installed Python distribution name does not match")
    if metadata.get("Version") != python_lock.get("version"):
        raise DeploymentError("installed Python distribution version does not match")
    direct_url = _mapping(
        _bounded_json(
            _read_bounded(
                dist_info / "direct_url.json",
                maximum=64 * 1024,
                label="PEP 610 receipt",
            ),
            "PEP 610 receipt",
        ),
        "PEP 610 receipt",
    )
    wheel = _wheel_path(direct_url, str(python_lock.get("wheel_sha256")))
    wheel_bytes = _read_bounded(
        wheel,
        maximum=MAX_ARTIFACT_BYTES,
        label="Python wheel",
    )
    wheel_digest = _sha256_bytes(wheel_bytes)
    if wheel_digest != python_lock.get("wheel_sha256"):
        raise DeploymentError("Python wheel bytes do not match the lock")

    verified_files = 0
    total_bytes = 0
    try:
        with zipfile.ZipFile(wheel) as bundle:
            infos = bundle.infolist()
            names = [item.filename for item in infos]
            if len(names) > MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
                raise DeploymentError("Python wheel member list is invalid")
            for info in infos:
                pure = Path(info.filename)
                if pure.is_absolute() or ".." in pure.parts:
                    raise DeploymentError("Python wheel contains an unsafe path")
                if info.file_size < 0 or info.file_size > MAX_INSTALLED_SOURCE_BYTES:
                    raise DeploymentError("Python wheel member exceeds its limit")
            entry_points = [
                item
                for item in infos
                if item.filename.endswith(".dist-info/entry_points.txt")
            ]
            if len(entry_points) != 1:
                raise DeploymentError("Python wheel entry points are ambiguous")
            if entry_points[0].file_size > 64 * 1024:
                raise DeploymentError("Python wheel entry points are oversized")
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(bundle.read(entry_points[0]).decode("utf-8"))
            if parser.get("console_scripts", "echo-veil-agent", fallback="") != (
                "echo_veil.agent_cli:main"
            ):
                raise DeploymentError("Python wheel console entry point is invalid")
            for info in infos:
                name = info.filename
                pure = Path(name)
                if not (
                    name.startswith("echo_veil/")
                    or name.startswith("echo_veil_origin/")
                ) or name.endswith("/"):
                    continue
                total_bytes += info.file_size
                if total_bytes > MAX_INSTALLED_SOURCE_BYTES:
                    raise DeploymentError("installed Python source exceeds its limit")
                payload = bundle.read(name)
                if len(payload) != info.file_size:
                    raise DeploymentError("Python wheel member size is inconsistent")
                installed = site_packages.joinpath(*pure.parts)
                if installed.is_symlink():
                    raise DeploymentError(
                        "installed Python source must not be a symlink"
                    )
                try:
                    installed_resolved = installed.resolve(strict=True)
                    installed_resolved.relative_to(site_packages)
                except (OSError, ValueError) as exc:
                    raise DeploymentError(
                        "installed Python source escapes its environment"
                    ) from exc
                if (
                    _read_bounded(
                        installed_resolved,
                        maximum=MAX_INSTALLED_SOURCE_BYTES,
                        label="installed Python source",
                    )
                    != payload
                ):
                    raise DeploymentError(
                        "installed Python source differs from its wheel"
                    )
                verified_files += 1
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise DeploymentError("Python wheel is invalid") from exc
    if verified_files < 1:
        raise DeploymentError("Python wheel contains no installable package source")
    return {
        "version": metadata.get("Version"),
        "wheel_sha256": wheel_digest,
        "installed_files_verified": verified_files,
        "artifact_bound": True,
    }


def _require(
    failures: list[str],
    condition: bool,
    code: str,
) -> None:
    if not condition:
        failures.append(code)


def evaluate_openclaw_state(
    *,
    lock: Mapping[str, Any],
    status: Mapping[str, Any],
    inspection: Mapping[str, Any],
    audit: Mapping[str, Any],
    config: Mapping[str, Any],
    memory_core_absent: bool,
    agent_id: str,
) -> list[str]:
    """Return stable failure codes for configuration/runtime drift."""

    failures: list[str] = []
    plugin_lock = _mapping(lock.get("plugin"), "plugin lock")
    profile_lock = _mapping(lock.get("profile"), "profile lock")
    plugin = _mapping(inspection.get("plugin"), "plugin inspection")
    service = _mapping(status.get("service"), "gateway service")
    runtime = _mapping(service.get("runtime"), "gateway runtime")
    rpc = _mapping(status.get("rpc"), "gateway RPC")
    gateway = _mapping(status.get("gateway"), "gateway status")
    drift = _mapping(status.get("pluginVersionDrift"), "plugin version drift").get(
        "drifts"
    )

    _require(failures, runtime.get("status") == "running", "gateway_not_running")
    _require(failures, rpc.get("ok") is True, "gateway_rpc_unhealthy")
    _require(
        failures,
        _mapping(rpc.get("server"), "gateway server").get("version")
        == lock.get("openclaw_version"),
        "openclaw_version_mismatch",
    )
    _require(failures, gateway.get("bindHost") == "127.0.0.1", "gateway_not_loopback")
    _require(failures, drift == [], "plugin_version_drift")

    _require(failures, plugin.get("id") == plugin_lock.get("id"), "wrong_plugin")
    _require(
        failures,
        plugin.get("version") == plugin_lock.get("version"),
        "plugin_version_mismatch",
    )
    _require(failures, plugin.get("status") == "loaded", "plugin_not_loaded")
    _require(failures, plugin.get("activated") is True, "plugin_not_activated")
    _require(
        failures,
        plugin.get("memorySlotSelected") is True,
        "memory_slot_not_selected",
    )
    tool_names = plugin.get("toolNames")
    _require(
        failures,
        isinstance(tool_names, list)
        and len(tool_names) == len(REQUIRED_TOOLS)
        and set(tool_names) == REQUIRED_TOOLS,
        "nine_tool_contract_missing",
    )
    hooks = inspection.get("typedHooks")
    hook_names = (
        {item.get("name") for item in hooks if isinstance(item, Mapping)}
        if isinstance(hooks, list)
        else set()
    )
    _require(
        failures,
        len(hook_names) == len(REQUIRED_HOOKS) and hook_names == REQUIRED_HOOKS,
        "protected_hook_contract_missing",
    )
    _require(failures, inspection.get("diagnostics") == [], "plugin_diagnostics")

    echo_entry = _mapping(config.get("echo_entry"), "Echo plugin config")
    echo_config = _mapping(echo_entry.get("config"), "Echo adapter config")
    echo_hooks = _mapping(echo_entry.get("hooks"), "Echo hook permissions")
    _require(failures, echo_entry.get("enabled") is True, "echo_disabled")
    _require(
        failures,
        echo_hooks.get("allowConversationAccess") is True,
        "conversation_access_disabled",
    )
    _require(
        failures,
        echo_hooks.get("allowPromptInjection") is True,
        "prompt_injection_disabled",
    )
    _require(
        failures,
        echo_config.get("profile") == profile_lock.get("id"),
        "profile_mismatch",
    )
    _require(
        failures,
        isinstance(echo_config.get("executable"), str)
        and bool(str(echo_config.get("executable")).strip()),
        "explicit_executable_missing",
    )
    _require(
        failures,
        not echo_config.get("projectPath"),
        "mutable_project_path_configured",
    )
    _require(
        failures,
        config.get("memory_slot") == plugin_lock.get("id"),
        "exclusive_memory_slot_missing",
    )
    _require(
        failures,
        config.get("session_memory_enabled") is False,
        "native_session_memory_enabled",
    )
    _require(
        failures,
        config.get("plugin_load_paths") in (None, []),
        "mutable_plugin_load_path_configured",
    )
    allowlist = config.get("plugin_allowlist")
    _require(
        failures,
        isinstance(allowlist, list) and plugin_lock.get("id") in allowlist,
        "plugin_not_allowlisted",
    )
    _require(failures, memory_core_absent, "stale_memory_core_config")

    agents = config.get("agents")
    main_agents = (
        [
            item
            for item in agents
            if isinstance(item, Mapping) and item.get("id") == agent_id
        ]
        if isinstance(agents, list)
        else []
    )
    _require(failures, len(main_agents) == 1, "agent_config_missing")
    if len(main_agents) == 1:
        also_allow = _mapping(main_agents[0].get("tools"), "agent tool policy").get(
            "alsoAllow"
        )
        _require(
            failures,
            isinstance(also_allow, list) and REQUIRED_TOOLS.issubset(also_allow),
            "agent_tool_allowlist_incomplete",
        )
    models = config.get("models")
    _require(
        failures,
        isinstance(models, Mapping)
        and bool(models)
        and all(
            isinstance(value, Mapping)
            and isinstance(value.get("agentRuntime"), Mapping)
            and value["agentRuntime"].get("id") == "openclaw"
            for value in models.values()
        ),
        "model_runtime_not_qualified",
    )

    _require(failures, config.get("gateway_bind") == "loopback", "unsafe_gateway_bind")
    _require(
        failures, config.get("gateway_auth_mode") == "token", "unsafe_gateway_auth"
    )
    _require(
        failures,
        config.get("allow_insecure_control_ui") is False,
        "insecure_control_ui_enabled",
    )
    _require(
        failures,
        config.get("trusted_proxies") == ["127.0.0.1"],
        "trusted_proxy_mismatch",
    )
    _require(
        failures,
        config.get("tailscale_mode") in {"off", "serve"},
        "unsafe_tailscale_mode",
    )

    summary = _mapping(audit.get("summary"), "security audit summary")
    _require(failures, summary.get("critical") == 0, "security_audit_critical")
    _require(failures, summary.get("warn") == 0, "security_audit_warning")
    _require(
        failures,
        audit.get("secretDiagnostics") in (None, []),
        "security_secret_diagnostics",
    )
    return failures


def _default_state_dir() -> Path:
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Echo Veil"
    if "XDG_DATA_HOME" in os.environ:
        return Path(os.environ["XDG_DATA_HOME"]).expanduser() / "echo-veil"
    return Path.home() / ".local" / "share" / "echo-veil"


def verify_owner_only_profile(state_dir: Path, profile: str) -> dict[str, object]:
    """Verify that the state parent, profile, and key directory are owner-only."""

    paths = (state_dir, state_dir / profile, state_dir / profile / "keys")
    for path in paths:
        if path.is_symlink():
            raise DeploymentError("profile state path must not be a symlink")
        try:
            mode = stat.S_IMODE(path.resolve(strict=True).stat().st_mode)
        except OSError as exc:
            raise DeploymentError("profile state path is unavailable") from exc
        if mode & 0o077:
            raise DeploymentError("profile state path is not owner-only")
    return {"owner_only": True, "checked_directories": len(paths)}


def run_doctor(
    executable_value: str,
    echo_config: Mapping[str, Any],
    lock: Mapping[str, Any],
) -> Mapping[str, Any]:
    """Run the now-artifact-bound read-only doctor command with a narrow env."""

    executable = _regular_path(
        executable_value,
        "Echo Veil executable",
        allow_final_symlink=True,
    )
    profile = _mapping(lock.get("profile"), "profile lock")
    environment = _safe_environment()
    environment.update(
        {
            "ECHO_VEIL_PROFILE": str(profile["id"]),
            "ECHO_VEIL_SCOPE": str(profile["scope"]),
            "ECHO_VEIL_CALLER": "openclaw",
            "ECHO_VEIL_EMBEDDER": str(profile["embedding_backend"]),
            "ECHO_VEIL_EMBEDDING_MODEL": str(profile["embedding_model"]),
            "ECHO_VEIL_EMBEDDING_DIMENSION": str(profile["embedding_dimension"]),
            "ECHO_VEIL_AVAILABILITY_LAYER": "true",
        }
    )
    state_dir = echo_config.get("stateDir")
    if isinstance(state_dir, str) and state_dir.strip():
        environment["ECHO_VEIL_STATE_DIR"] = state_dir.strip()
    try:
        completed = subprocess.run(  # noqa: S603 -- artifact-bound executable
            [str(executable), "--profile", str(profile["id"]), "doctor"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=environment,
            shell=False,
            check=False,
            timeout=DOCTOR_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise DeploymentError("Echo Veil doctor failed") from exc
    if completed.returncode != 0:
        raise DeploymentError("Echo Veil doctor reported an error")
    return _mapping(
        _bounded_json(completed.stdout, "Echo Veil doctor"), "Echo Veil doctor"
    )


def evaluate_doctor(
    doctor: Mapping[str, Any],
    lock: Mapping[str, Any],
    *,
    require_production_ready: bool,
) -> list[str]:
    failures: list[str] = []
    readiness = _mapping(doctor.get("readiness"), "doctor readiness")
    layers = _mapping(doctor.get("memory_layers"), "doctor memory layers")
    retrieval = _mapping(doctor.get("retrieval"), "doctor retrieval")
    embedding = _mapping(doctor.get("embedding"), "doctor embedding")
    profile = _mapping(lock.get("profile"), "profile lock")
    for field in (
        "enabled",
        "healthy",
        "installed",
        "write_wired",
        "retrieval_wired",
        "persistence_wired",
        "restart_restored",
        "layer_contract_wired",
        "live_refresh_wired",
        "competing_memory_wired",
        "context_trace_wired",
    ):
        _require(failures, readiness.get(field) is True, f"doctor_{field}_false")
    _require(
        failures,
        doctor.get("profile") == profile.get("id"),
        "doctor_profile_mismatch",
    )
    _require(
        failures,
        embedding.get("backend") == profile.get("embedding_backend")
        and embedding.get("model") == profile.get("embedding_model")
        and embedding.get("dimension") == profile.get("embedding_dimension")
        and embedding.get("semantic") is True,
        "doctor_embedding_mismatch",
    )
    _require(
        failures,
        layers.get("all_records_shielded") is True
        and layers.get("unprotected_record_count") == 0
        and layers.get("unpaired_lifecycle_record_count") == 0,
        "doctor_unshielded_records",
    )
    _require(
        failures,
        doctor.get("failed_decryptions") == 0
        and doctor.get("plaintext_fallback_attempts") == 0
        and doctor.get("reconciliation_backlog") == 0
        and retrieval.get("unindexed_payload_count") == 0,
        "doctor_integrity_failure",
    )
    _require(
        failures,
        doctor.get("store_permissions") == "valid"
        and doctor.get("key_owner_only") is True,
        "doctor_permissions_invalid",
    )
    if require_production_ready:
        _require(
            failures,
            doctor.get("production_ready") is True,
            "production_readiness_blocked",
        )
    return failures


def collect_config(client: OpenClawClient) -> tuple[dict[str, Any], bool]:
    """Collect only the configuration fields required by the deployment gate."""

    memory_core = client.config(
        "plugins.entries.memory-core",
        allow_missing=True,
    )
    return (
        {
            "echo_entry": client.config("plugins.entries.echo-veil"),
            "memory_slot": client.config("plugins.slots.memory"),
            "session_memory_enabled": client.config(
                "hooks.internal.entries.session-memory.enabled"
            ),
            "plugin_load_paths": client.config(
                "plugins.load.paths",
                allow_missing=True,
            ),
            "plugin_allowlist": client.config("plugins.allow"),
            "agents": client.config("agents.list"),
            "models": client.config("agents.defaults.models"),
            "gateway_bind": client.config("gateway.bind"),
            "gateway_auth_mode": client.config("gateway.auth.mode"),
            "allow_insecure_control_ui": client.config(
                "gateway.controlUi.allowInsecureAuth"
            ),
            "trusted_proxies": client.config("gateway.trustedProxies"),
            "tailscale_mode": client.config("gateway.tailscale.mode"),
        },
        memory_core is None,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify a live OpenClaw/Echo Veil deployment against immutable "
            "artifacts and the singular-memory policy."
        )
    )
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    parser.add_argument("--agent-id", default="main")
    parser.add_argument(
        "--require-production-ready",
        action="store_true",
        help="also fail unless the configured CryptoShield is production-ready",
    )
    parser.add_argument("--text", action="store_true")
    return parser


def _text_report(report: Mapping[str, object]) -> str:
    lines = [
        "Echo Veil OpenClaw deployment",
        f"status: {report['status']}",
        f"deployment mode: {report['deployment_mode']}",
        f"OpenClaw: {report['openclaw_version']}",
        f"tools: {report['tool_count']}/9",
        f"hooks: {report['hook_count']}/3",
        f"artifact bound: {str(report['artifact_bound']).lower()}",
        f"records shielded: {str(report['all_records_shielded']).lower()}",
        f"production ready: {str(report['production_ready']).lower()}",
    ]
    failures = report.get("failures")
    if isinstance(failures, list):
        lines.extend(f"- {item}" for item in failures)
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if PROFILE_ID.fullmatch(args.agent_id) is None:
        print(
            json.dumps(
                {
                    "error": "deployment_verification_invalid",
                    "message": "agent id is invalid",
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1
    try:
        lock = load_lock(args.lock)
        client = OpenClawClient()
        status = _mapping(
            client.json(("gateway", "status", "--json"), "gateway status"),
            "gateway status",
        )
        inspection = _mapping(
            client.json(
                ("plugins", "inspect", "echo-veil", "--runtime", "--json"),
                "plugin inspection",
            ),
            "plugin inspection",
        )
        audit = _mapping(
            client.json(("security", "audit", "--json"), "security audit"),
            "security audit",
        )
        config, memory_core_absent = collect_config(client)
        failures = evaluate_openclaw_state(
            lock=lock,
            status=status,
            inspection=inspection,
            audit=audit,
            config=config,
            memory_core_absent=memory_core_absent,
            agent_id=args.agent_id,
        )
        plugin_receipt = verify_plugin_artifact(inspection, lock)
        echo_entry = _mapping(config.get("echo_entry"), "Echo plugin config")
        echo_config = _mapping(echo_entry.get("config"), "Echo adapter config")
        executable = _string(
            echo_config.get("executable"),
            "Echo Veil executable",
            maximum=4_096,
        )
        python_receipt = verify_python_artifact(executable, lock)
        doctor = run_doctor(executable, echo_config, lock)
        failures.extend(
            evaluate_doctor(
                doctor,
                lock,
                require_production_ready=args.require_production_ready,
            )
        )
        state_value = echo_config.get("stateDir")
        state_dir = (
            Path(state_value).expanduser()
            if isinstance(state_value, str) and state_value.strip()
            else _default_state_dir()
        )
        profile_receipt = verify_owner_only_profile(
            state_dir,
            str(_mapping(lock["profile"], "profile lock")["id"]),
        )
        plugin = _mapping(inspection.get("plugin"), "plugin inspection")
        layers = _mapping(doctor.get("memory_layers"), "doctor memory layers")
        production_ready = doctor.get("production_ready") is True
        report: dict[str, object] = {
            "schema_version": 1,
            "status": "pass" if not failures else "fail",
            "deployment_mode": ("production" if production_ready else "local-staging"),
            "openclaw_version": lock["openclaw_version"],
            "tool_count": len(plugin.get("toolNames", [])),
            "hook_count": plugin.get("hookCount"),
            "artifact_bound": (
                plugin_receipt["artifact_bound"] and python_receipt["artifact_bound"]
            ),
            "plugin_archive_sha256": plugin_receipt["archive_sha256"],
            "plugin_entrypoint_sha256": plugin_receipt["entrypoint_sha256"],
            "python_wheel_sha256": python_receipt["wheel_sha256"],
            "installed_python_files_verified": python_receipt[
                "installed_files_verified"
            ],
            "profile_directories_owner_only": profile_receipt["owner_only"],
            "payload_count": doctor.get("payload_count"),
            "all_records_shielded": layers.get("all_records_shielded"),
            "production_ready": production_ready,
            "failures": sorted(set(failures)),
        }
        print(
            _text_report(report)
            if args.text
            else json.dumps(report, sort_keys=True, separators=(",", ":"))
        )
        return 0 if not failures else 2
    except (DeploymentError, OSError) as exc:
        print(
            json.dumps(
                {
                    "error": "deployment_verification_invalid",
                    "message": str(exc),
                },
                sort_keys=True,
                separators=(",", ":"),
            ),
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
