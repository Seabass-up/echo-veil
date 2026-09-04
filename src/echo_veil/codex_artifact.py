"""Path-free artifact receipts for the singular Codex runtime boundary."""

from __future__ import annotations

import configparser
import hashlib
import hmac
import io
import json
import os
import re
import stat
import urllib.parse
import zipfile
from dataclasses import dataclass
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Any

from ._json import strict_json_loads

CODEX_ARTIFACT_SCHEMA = "echo-veil-codex-artifact-v1"
CODEX_ARTIFACT_DOMAIN = b"echo-veil-codex-artifact-v1\0"
EXPECTED_CODEX_VERSION = "0.149.1"
MAX_ARTIFACT_FILE_BYTES = 512 * 1024 * 1024
MAX_PLUGIN_FILE_BYTES = 2 * 1024 * 1024
MAX_WHEEL_MEMBERS = 4_096
MAX_INSTALLED_SOURCE_BYTES = 64 * 1024 * 1024
SHA256_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")

CODEX_PLUGIN_FILES = (
    ".agents/plugins/marketplace.json",
    ".codex-plugin/plugin.json",
    ".mcp.json",
    "hooks/hooks.json",
    "skills/echo-veil-memory/SKILL.md",
    "skills/echo-veil-memory/agents/openai.yaml",
)


class CodexArtifactError(RuntimeError):
    """The configured Codex boundary is mutable, incomplete, or unbound."""


@dataclass(frozen=True)
class CodexArtifactBundle:
    authority_id: str
    plugin_payloads: dict[str, bytes]
    receipt: dict[str, Any]


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _read_regular(path: Path, *, maximum: int) -> bytes:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0),
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > maximum
            or before.st_mode & 0o022
        ):
            raise CodexArtifactError("artifact file is unsafe")
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise CodexArtifactError("artifact file changed during verification")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
        if (
            after.st_size != before.st_size
            or after.st_ino != before.st_ino
            or after.st_dev != before.st_dev
        ):
            raise CodexArtifactError("artifact file changed during verification")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _file_identity(path: Path) -> dict[str, object]:
    payload = _read_regular(path, maximum=MAX_ARTIFACT_FILE_BYTES)
    return {
        "sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
        "size": len(payload),
    }


def _resolved_executable(value: str, label: str) -> Path:
    path = Path(value).expanduser()
    if not path.is_absolute():
        raise CodexArtifactError(f"{label} must be an absolute path")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise CodexArtifactError(f"{label} is unavailable") from exc
    if not resolved.is_file() or not os.access(resolved, os.X_OK):
        raise CodexArtifactError(f"{label} is not executable")
    return resolved


def _console_interpreter(script: Path) -> tuple[Path, bytes]:
    payload = _read_regular(script, maximum=64 * 1024)
    try:
        shebang, body = payload.split(b"\n", 1)
        interpreter_value = shebang[2:].decode("utf-8")
    except (UnicodeDecodeError, ValueError) as exc:
        raise CodexArtifactError("Echo console script is invalid") from exc
    if not shebang.startswith(b"#!/") or not interpreter_value.startswith("/"):
        raise CodexArtifactError("Echo console script interpreter is invalid")
    # Keep the lexical virtual-environment path so its site-packages directory
    # can be derived below.  Resolving the common ``bin/python`` symlink would
    # instead point at the shared/base interpreter and lose the environment
    # that owns these console scripts.  We still resolve once here to prove the
    # shebang target exists and is executable.
    _resolved_executable(interpreter_value, "Echo Python interpreter")
    return Path(interpreter_value), body


def _wheel_from_direct_url(dist_info: Path) -> tuple[Path, str]:
    direct = strict_json_loads(
        _read_regular(dist_info / "direct_url.json", maximum=64 * 1024)
    )
    if not isinstance(direct, dict) or set(direct) - {
        "archive_info",
        "subdirectory",
        "url",
    }:
        raise CodexArtifactError("Echo PEP 610 receipt is invalid")
    parsed = urllib.parse.urlparse(str(direct.get("url", "")))
    archive = direct.get("archive_info")
    if (
        parsed.scheme != "file"
        or parsed.netloc not in {"", "localhost"}
        or not isinstance(archive, dict)
        or set(archive) - {"hash", "hashes"}
    ):
        raise CodexArtifactError("Echo must be installed from a retained local wheel")
    expected_digests: list[str] = []
    expected = archive.get("hash")
    if expected is not None:
        if not isinstance(expected, str) or not expected.startswith("sha256="):
            raise CodexArtifactError("Echo wheel hash is invalid")
        expected_digests.append(expected.removeprefix("sha256="))
    hashes = archive.get("hashes")
    if hashes is not None:
        if not isinstance(hashes, dict) or set(hashes) != {"sha256"}:
            raise CodexArtifactError("Echo wheel hash is invalid")
        expected_digests.append(str(hashes["sha256"]))
    if parsed.fragment:
        try:
            fragment = urllib.parse.parse_qs(
                parsed.fragment,
                keep_blank_values=True,
                strict_parsing=True,
            )
        except ValueError as exc:
            raise CodexArtifactError("Echo wheel hash is invalid") from exc
        if set(fragment) != {"sha256"} or len(fragment["sha256"]) != 1:
            raise CodexArtifactError("Echo wheel hash is invalid")
        expected_digests.append(fragment["sha256"][0])
    if not expected_digests:
        raise CodexArtifactError("Echo wheel hash is unavailable")
    if any(not re.fullmatch(r"[0-9a-f]{64}", item) for item in expected_digests):
        raise CodexArtifactError("Echo wheel hash is invalid")
    digest = expected_digests[0]
    if any(not hmac.compare_digest(digest, item) for item in expected_digests[1:]):
        raise CodexArtifactError("Echo wheel hashes disagree")
    wheel = Path(urllib.parse.unquote(parsed.path)).resolve(strict=True)
    return wheel, digest


def _verify_echo_wheel(
    agent_executable: Path,
    hook_executable: Path,
) -> dict[str, object]:
    agent_interpreter, agent_body = _console_interpreter(agent_executable)
    hook_interpreter, hook_body = _console_interpreter(hook_executable)
    if agent_interpreter != hook_interpreter:
        raise CodexArtifactError("Echo console scripts use different environments")
    environment = agent_interpreter.parent.parent
    candidates = sorted((environment / "lib").glob("python*/site-packages"))
    if len(candidates) != 1 or candidates[0].is_symlink():
        raise CodexArtifactError("Echo site-packages is ambiguous")
    site_packages = candidates[0].resolve(strict=True)
    dist_infos = sorted(site_packages.glob("echo_veil-*.dist-info"))
    if len(dist_infos) != 1 or dist_infos[0].is_symlink():
        raise CodexArtifactError("Echo distribution metadata is ambiguous")
    dist_info = dist_infos[0].resolve(strict=True)
    metadata = BytesParser().parsebytes(
        _read_regular(dist_info / "METADATA", maximum=512 * 1024)
    )
    if metadata.get("Name") != "echo-veil":
        raise CodexArtifactError("Echo distribution name is invalid")
    version = metadata.get("Version")
    if not isinstance(version, str) or not version or len(version) > 128:
        raise CodexArtifactError("Echo distribution version is invalid")
    wheel, expected_wheel_digest = _wheel_from_direct_url(dist_info)
    wheel_payload = _read_regular(wheel, maximum=MAX_ARTIFACT_FILE_BYTES)
    wheel_digest = hashlib.sha256(wheel_payload).hexdigest()
    if wheel_digest != expected_wheel_digest:
        raise CodexArtifactError("Echo wheel differs from its PEP 610 receipt")

    installed_files = 0
    installed_bytes = 0
    installed_source_digest = hashlib.sha256()
    try:
        with zipfile.ZipFile(io.BytesIO(wheel_payload)) as bundle:
            infos = bundle.infolist()
            names = [info.filename for info in infos]
            if len(names) > MAX_WHEEL_MEMBERS or len(names) != len(set(names)):
                raise CodexArtifactError("Echo wheel member list is invalid")
            entry_points = [
                info
                for info in infos
                if info.filename.endswith(".dist-info/entry_points.txt")
            ]
            if len(entry_points) != 1 or entry_points[0].file_size > 64 * 1024:
                raise CodexArtifactError("Echo wheel entry points are invalid")
            parser = configparser.ConfigParser(interpolation=None)
            parser.read_string(bundle.read(entry_points[0]).decode("utf-8"))
            required = {
                "echo-veil-agent": "echo_veil.agent_cli:main",
                "echo-veil-preflight-hook": "echo_veil.agent_preflight:main",
                "echo-veil-shielded-run": "echo_veil.guarded_runner:main",
            }
            for name, target in required.items():
                if parser.get("console_scripts", name, fallback="") != target:
                    raise CodexArtifactError(
                        "Echo wheel console entry point is invalid"
                    )
            for info in sorted(infos, key=lambda item: item.filename):
                pure = PurePosixPath(info.filename)
                if pure.is_absolute() or ".." in pure.parts:
                    raise CodexArtifactError("Echo wheel path is unsafe")
                if (
                    info.is_dir()
                    or not pure.parts
                    or pure.parts[0]
                    not in {
                        "echo_veil",
                        "echo_veil_origin",
                    }
                ):
                    continue
                installed_bytes += info.file_size
                if installed_bytes > MAX_INSTALLED_SOURCE_BYTES:
                    raise CodexArtifactError("Echo installed source exceeds its limit")
                payload = bundle.read(info)
                installed_source_digest.update(info.filename.encode("utf-8"))
                installed_source_digest.update(b"\0")
                installed_source_digest.update(payload)
                installed_source_digest.update(b"\0")
                installed = site_packages.joinpath(*pure.parts)
                if (
                    installed.is_symlink()
                    or _read_regular(
                        installed,
                        maximum=MAX_INSTALLED_SOURCE_BYTES,
                    )
                    != payload
                ):
                    raise CodexArtifactError(
                        "Echo installed source differs from its wheel"
                    )
                installed_files += 1
    except (OSError, UnicodeDecodeError, zipfile.BadZipFile) as exc:
        raise CodexArtifactError("Echo wheel is invalid") from exc
    if installed_files < 1:
        raise CodexArtifactError("Echo wheel contains no package source")
    return {
        "agent_console_body_sha256": (
            f"sha256:{hashlib.sha256(agent_body).hexdigest()}"
        ),
        "hook_console_body_sha256": (f"sha256:{hashlib.sha256(hook_body).hexdigest()}"),
        "installed_files_verified": installed_files,
        "installed_source_sha256": (f"sha256:{installed_source_digest.hexdigest()}"),
        "version": version,
        "wheel_sha256": f"sha256:{wheel_digest}",
    }


def _plugin_payloads(root_value: str) -> dict[str, bytes]:
    root = Path(root_value).expanduser()
    if not root.is_absolute() or root.is_symlink():
        raise CodexArtifactError("Codex plugin root must be an absolute directory")
    root = root.resolve(strict=True)
    details = root.stat()
    if not stat.S_ISDIR(details.st_mode) or details.st_mode & 0o022:
        raise CodexArtifactError("Codex plugin root is unsafe")
    payloads: dict[str, bytes] = {}
    for relative in CODEX_PLUGIN_FILES:
        path = root.joinpath(*PurePosixPath(relative).parts)
        payloads[relative] = _read_regular(path, maximum=MAX_PLUGIN_FILE_BYTES)
    return payloads


def build_codex_artifact_bundle(
    *,
    codex_executable: str,
    echo_agent_executable: str,
    echo_hook_executable: str,
    plugin_root: str,
    model: str,
    mode: str,
    configuration: dict[str, object],
) -> CodexArtifactBundle:
    """Build one path-free receipt over every executable and config boundary."""

    if mode not in {"headless", "interactive"}:
        raise CodexArtifactError("Codex artifact mode is invalid")
    if not isinstance(model, str) or not model or len(model) > 256:
        raise CodexArtifactError("Codex model is invalid")
    codex = _resolved_executable(codex_executable, "Codex executable")
    agent = _resolved_executable(echo_agent_executable, "Echo agent executable")
    hook = _resolved_executable(echo_hook_executable, "Echo hook executable")
    payloads = _plugin_payloads(plugin_root)
    file_digests = {
        name: f"sha256:{hashlib.sha256(payload).hexdigest()}"
        for name, payload in sorted(payloads.items())
    }
    claims = {
        "codex_executable": {
            **_file_identity(codex),
            "version": EXPECTED_CODEX_VERSION,
        },
        "configuration": configuration,
        "echo_python": _verify_echo_wheel(agent, hook),
        "host": "codex",
        "hook_manifest_digest": file_digests["hooks/hooks.json"],
        "mcp_manifest_digest": file_digests[".mcp.json"],
        "mode": mode,
        "model_digest": (f"sha256:{hashlib.sha256(model.encode('utf-8')).hexdigest()}"),
        "plugin_files": file_digests,
        "plugin_manifest_digest": file_digests[".codex-plugin/plugin.json"],
        "schema": CODEX_ARTIFACT_SCHEMA,
    }
    authority_id = (
        "sha256:"
        + hashlib.sha256(CODEX_ARTIFACT_DOMAIN + _canonical_json(claims)).hexdigest()
    )
    return CodexArtifactBundle(
        authority_id=authority_id,
        plugin_payloads=payloads,
        receipt={
            "artifact_authority_id": authority_id,
            "claims": claims,
            "schema": CODEX_ARTIFACT_SCHEMA,
        },
    )


def verify_codex_artifact_pin(
    bundle: CodexArtifactBundle,
    expected_authority_id: str | None,
) -> None:
    if not isinstance(expected_authority_id, str) or not SHA256_ID.fullmatch(
        expected_authority_id
    ):
        raise CodexArtifactError("Codex artifact authority must be explicitly pinned")
    if not hmac.compare_digest(
        bundle.authority_id,
        expected_authority_id,
    ):
        raise CodexArtifactError("Codex artifact authority binding is invalid")
