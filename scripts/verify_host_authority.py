#!/usr/bin/env python3
"""Audit bounded Echo Veil host-authority evidence without exposing secrets.

This verifier deliberately separates repository evidence from installed-runtime
evidence. An adapter file, executable, or matching version is not by itself
proof that a host blocks model execution when Echo Veil is unavailable. Runtime
evidence becomes current only when the recorded source digests and tested host
version still match.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path, PurePosixPath
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = ROOT / "integrations" / "authority-evidence.json"
MAX_MANIFEST_BYTES = 256 * 1024
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
MAX_VERSION_OUTPUT_BYTES = 16 * 1024
MAX_RECEIPT_OUTPUT_BYTES = 64 * 1024
VERSION_TIMEOUT_SECONDS = 10.0
HOST_ID = re.compile(r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
DATE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")
ARTIFACT_BINDING_KIND = "pep610-wheel-sha256-v1"
EVIDENCE_STATES = frozenset(
    {
        "qualified",
        "conditional",
        "external_unbound",
        "repository_only",
        "blocked",
    }
)

# Fixed, read-only commands prevent a repository document from turning this
# verifier into an arbitrary subprocess launcher.
VERSION_COMMANDS: dict[str, tuple[str, ...]] = {
    "aip": ("aip", "--version"),
    "algo-cli": ("algo-cli", "--version"),
    "openclaw": ("openclaw", "--version"),
    "hermes": ("hermes", "--version"),
    "codex": ("codex", "--version"),
    "claude-code": ("claude", "--version"),
    "pi": ("pi", "--version"),
    "opencode": ("opencode", "--version"),
    "droid": ("droid", "--version"),
    "goose": ("goose", "--version"),
}
VERSION_EXTRACTORS: dict[str, re.Pattern[str]] = {
    "aip": re.compile(r"^aip ([0-9][0-9A-Za-z.+-]*)\b", re.MULTILINE),
    "algo-cli": re.compile(r"\bAlgo CLI v([0-9][0-9A-Za-z.+-]*)\b"),
    "openclaw": re.compile(r"\bOpenClaw ([0-9][0-9A-Za-z.+-]*)\b"),
    "hermes": re.compile(r"\bHermes Agent v([0-9][0-9A-Za-z.+-]*)\b"),
    "codex": re.compile(r"\bcodex-cli ([0-9][0-9A-Za-z.+-]*)\b"),
    "claude-code": re.compile(r"^([0-9][0-9A-Za-z.+-]*)\b", re.MULTILINE),
    "pi": re.compile(r"^([0-9][0-9A-Za-z.+-]*)\b", re.MULTILINE),
    "opencode": re.compile(r"^([0-9][0-9A-Za-z.+-]*)\b", re.MULTILINE),
    "droid": re.compile(r"^([0-9][0-9A-Za-z.+-]*)\b", re.MULTILINE),
    "goose": re.compile(r"\b([0-9]+(?:\.[0-9]+){2}[0-9A-Za-z.+-]*)\b"),
}
ARTIFACT_RECEIPT_COMMANDS: dict[str, tuple[str, ...]] = {
    "aip": ("aip", "authority-receipt"),
}
ARTIFACT_RECEIPT_FIELDS = frozenset(
    {
        "schema_version",
        "distribution",
        "version",
        "memory_contract",
        "profile",
        "scope",
        "caller",
        "plaintext_fallback",
        "artifact_bound",
        "artifact_sha256",
        "installed_source_sha256",
        "record_integrity",
    }
)


class ManifestError(ValueError):
    """The authority evidence manifest is malformed or unsafe."""


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise ManifestError(f"duplicate JSON key: {key}")
        output[key] = value
    return output


def _reject_json_constant(value: str) -> None:
    raise ManifestError(f"invalid receipt JSON constant: {value}")


def load_manifest(path: Path) -> dict[str, Any]:
    """Read one bounded, duplicate-key-free authority manifest."""

    raw = path.read_bytes()
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ManifestError("authority manifest exceeds size limit")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ManifestError("authority manifest is invalid JSON") from exc
    if not isinstance(value, dict):
        raise ManifestError("authority manifest must be a JSON object")
    return value


def _required_string(value: object, field: str, *, maximum: int = 2_000) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ManifestError(f"{field} must be a bounded non-empty string")
    if any(ord(character) < 0x20 for character in value):
        raise ManifestError(f"{field} contains control characters")
    return value


def _string_list(
    value: object,
    field: str,
    *,
    maximum_items: int = 32,
    maximum_chars: int = 2_000,
) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ManifestError(f"{field} must be a bounded string list")
    output = [
        _required_string(item, f"{field} item", maximum=maximum_chars) for item in value
    ]
    if len(set(output)) != len(output):
        raise ManifestError(f"{field} contains duplicate values")
    return output


def _artifact_path(root: Path, relative: str) -> Path:
    pure = PurePosixPath(relative)
    if pure.is_absolute() or ".." in pure.parts or not pure.parts:
        raise ManifestError(f"unsafe artifact path: {relative}")
    candidate = root.joinpath(*pure.parts)
    if candidate.is_symlink():
        raise ManifestError(f"artifact must not be a symlink: {relative}")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ManifestError(f"artifact is missing: {relative}") from exc
    try:
        resolved.relative_to(root.resolve(strict=True))
    except ValueError as exc:
        raise ManifestError(f"artifact escapes repository root: {relative}") from exc
    if not resolved.is_file():
        raise ManifestError(f"artifact is not a file: {relative}")
    return resolved


def artifact_digest(root: Path, relative_paths: Sequence[str]) -> str:
    """Hash paths and bytes in stable order, rejecting oversized artifacts."""

    digest = hashlib.sha256()
    for relative in sorted(relative_paths):
        path = _artifact_path(root, relative)
        size = path.stat().st_size
        if size > MAX_ARTIFACT_BYTES:
            raise ManifestError(f"artifact exceeds size limit: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return f"sha256:{digest.hexdigest()}"


def validate_manifest(root: Path, manifest: Mapping[str, object]) -> dict[str, Any]:
    """Validate and normalize the complete evidence document."""

    expected_top = {
        "schema_version",
        "profile",
        "scope",
        "shared_source_artifacts",
        "shared_source_digest",
        "hosts",
        "limitations",
    }
    extras = set(manifest) - expected_top
    if extras:
        raise ManifestError(
            f"authority manifest contains unexpected fields: {sorted(extras)}"
        )
    if manifest.get("schema_version") != 1:
        raise ManifestError("unsupported authority manifest schema")
    profile = _required_string(manifest.get("profile"), "profile", maximum=128)
    scope = _required_string(manifest.get("scope"), "scope", maximum=128)
    shared_paths = _string_list(
        manifest.get("shared_source_artifacts"),
        "shared_source_artifacts",
        maximum_items=32,
        maximum_chars=240,
    )
    shared_expected = _required_string(
        manifest.get("shared_source_digest"),
        "shared_source_digest",
        maximum=71,
    )
    if not SHA256.fullmatch(shared_expected):
        raise ManifestError("shared_source_digest is not a SHA-256 digest")
    limitations = _string_list(
        manifest.get("limitations"),
        "limitations",
        maximum_items=16,
    )
    host_values = manifest.get("hosts")
    if not isinstance(host_values, list) or not host_values or len(host_values) > 32:
        raise ManifestError("hosts must be a bounded non-empty list")

    hosts: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected_host = {
        "id",
        "display_name",
        "adapter",
        "evidence_state",
        "qualified_boundary",
        "tested_on",
        "tested_version",
        "artifact_binding",
        "source_artifacts",
        "source_digest",
        "checks",
        "remaining",
    }
    for raw_host in host_values:
        if not isinstance(raw_host, dict):
            raise ManifestError("each host must be a JSON object")
        extras = set(raw_host) - expected_host
        if extras:
            raise ManifestError(f"host contains unexpected fields: {sorted(extras)}")
        host_id = _required_string(raw_host.get("id"), "host id", maximum=64)
        if not HOST_ID.fullmatch(host_id) or host_id in seen:
            raise ManifestError(f"host id is invalid or duplicated: {host_id}")
        seen.add(host_id)
        display_name = _required_string(
            raw_host.get("display_name"), f"{host_id}.display_name", maximum=80
        )
        adapter = _required_string(
            raw_host.get("adapter"), f"{host_id}.adapter", maximum=240
        )
        evidence_state = _required_string(
            raw_host.get("evidence_state"),
            f"{host_id}.evidence_state",
            maximum=32,
        )
        if evidence_state not in EVIDENCE_STATES:
            raise ManifestError(f"{host_id}.evidence_state is unsupported")
        boundary = _required_string(
            raw_host.get("qualified_boundary"),
            f"{host_id}.qualified_boundary",
        )
        tested_on = _required_string(
            raw_host.get("tested_on"), f"{host_id}.tested_on", maximum=10
        )
        if not DATE.fullmatch(tested_on):
            raise ManifestError(f"{host_id}.tested_on is not YYYY-MM-DD")
        tested_version_value = raw_host.get("tested_version")
        if tested_version_value is None:
            tested_version = None
        else:
            tested_version = _required_string(
                tested_version_value,
                f"{host_id}.tested_version",
                maximum=80,
            )
        if host_id in VERSION_COMMANDS and tested_version is None:
            raise ManifestError(f"{host_id} requires a tested_version")
        if host_id not in VERSION_COMMANDS and tested_version is not None:
            raise ManifestError(f"{host_id} cannot declare a tested_version")
        raw_binding = raw_host.get("artifact_binding")
        if raw_binding is None:
            artifact_binding = None
        else:
            if host_id not in ARTIFACT_RECEIPT_COMMANDS:
                raise ManifestError(
                    f"{host_id}.artifact_binding is not supported for this host"
                )
            expected_binding = {
                "kind",
                "distribution",
                "version",
                "sha256",
                "receipt_schema",
                "memory_contract",
                "profile",
                "scope",
                "caller",
                "plaintext_fallback",
            }
            if (
                not isinstance(raw_binding, dict)
                or set(raw_binding) != expected_binding
            ):
                raise ManifestError(
                    f"{host_id}.artifact_binding has an invalid field set"
                )
            kind = _required_string(
                raw_binding.get("kind"),
                f"{host_id}.artifact_binding.kind",
                maximum=64,
            )
            if kind != ARTIFACT_BINDING_KIND:
                raise ManifestError(f"{host_id}.artifact_binding.kind is unsupported")
            distribution = _required_string(
                raw_binding.get("distribution"),
                f"{host_id}.artifact_binding.distribution",
                maximum=128,
            )
            version = _required_string(
                raw_binding.get("version"),
                f"{host_id}.artifact_binding.version",
                maximum=80,
            )
            digest = _required_string(
                raw_binding.get("sha256"),
                f"{host_id}.artifact_binding.sha256",
                maximum=64,
            )
            if HEX_SHA256.fullmatch(digest) is None:
                raise ManifestError(f"{host_id}.artifact_binding.sha256 is not SHA-256")
            if raw_binding.get("receipt_schema") != 1:
                raise ManifestError(
                    f"{host_id}.artifact_binding.receipt_schema is unsupported"
                )
            memory_contract = _required_string(
                raw_binding.get("memory_contract"),
                f"{host_id}.artifact_binding.memory_contract",
                maximum=128,
            )
            binding_profile = _required_string(
                raw_binding.get("profile"),
                f"{host_id}.artifact_binding.profile",
                maximum=128,
            )
            binding_scope = _required_string(
                raw_binding.get("scope"),
                f"{host_id}.artifact_binding.scope",
                maximum=128,
            )
            caller = _required_string(
                raw_binding.get("caller"),
                f"{host_id}.artifact_binding.caller",
                maximum=64,
            )
            if raw_binding.get("plaintext_fallback") is not False:
                raise ManifestError(
                    f"{host_id}.artifact_binding.plaintext_fallback must be false"
                )
            if (
                version != tested_version
                or binding_profile != profile
                or binding_scope != scope
                or caller != host_id
            ):
                raise ManifestError(
                    f"{host_id}.artifact_binding does not match its host authority"
                )
            artifact_binding = {
                "kind": kind,
                "distribution": distribution,
                "version": version,
                "sha256": digest,
                "receipt_schema": 1,
                "memory_contract": memory_contract,
                "profile": binding_profile,
                "scope": binding_scope,
                "caller": caller,
                "plaintext_fallback": False,
            }
        if (
            host_id in ARTIFACT_RECEIPT_COMMANDS
            and evidence_state in {"qualified", "conditional"}
            and artifact_binding is None
        ):
            raise ManifestError(
                f"{host_id} requires artifact_binding for current runtime evidence"
            )
        source_paths = _string_list(
            raw_host.get("source_artifacts"),
            f"{host_id}.source_artifacts",
            maximum_items=32,
            maximum_chars=240,
        )
        source_expected = _required_string(
            raw_host.get("source_digest"),
            f"{host_id}.source_digest",
            maximum=71,
        )
        if not SHA256.fullmatch(source_expected):
            raise ManifestError(f"{host_id}.source_digest is not SHA-256")
        checks = _string_list(
            raw_host.get("checks"),
            f"{host_id}.checks",
            maximum_items=24,
        )
        remaining = _string_list(
            raw_host.get("remaining"),
            f"{host_id}.remaining",
            maximum_items=24,
        )
        hosts.append(
            {
                "id": host_id,
                "display_name": display_name,
                "adapter": adapter,
                "evidence_state": evidence_state,
                "qualified_boundary": boundary,
                "tested_on": tested_on,
                "tested_version": tested_version,
                "artifact_binding": artifact_binding,
                "source_artifacts": source_paths,
                "source_digest": source_expected,
                "checks": checks,
                "remaining": remaining,
            }
        )

    return {
        "schema_version": 1,
        "profile": profile,
        "scope": scope,
        "shared_source_artifacts": shared_paths,
        "shared_source_digest": shared_expected,
        "hosts": hosts,
        "limitations": limitations,
    }


def _version_environment() -> dict[str, str]:
    allowed = ("HOME", "LANG", "LC_ALL", "LC_CTYPE", "PATH", "TMPDIR")
    return {name: os.environ[name] for name in allowed if name in os.environ}


def probe_installed_version(host_id: str) -> dict[str, object]:
    """Run only the fixed version command for one known host."""

    command = VERSION_COMMANDS.get(host_id)
    extractor = VERSION_EXTRACTORS.get(host_id)
    if command is None or extractor is None:
        return {"status": "not_applicable", "version": None}
    executable = shutil.which(command[0])
    if executable is None:
        return {"status": "missing", "version": None}
    try:
        completed = subprocess.run(  # noqa: S603 -- fixed read-only argv above
            [str(Path(executable).resolve()), *command[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            env=_version_environment(),
            shell=False,
            check=False,
            timeout=VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "probe_failed", "version": None}
    output = completed.stdout[: MAX_VERSION_OUTPUT_BYTES + 1]
    if len(output) > MAX_VERSION_OUTPUT_BYTES:
        return {"status": "oversized_output", "version": None}
    if completed.returncode != 0:
        return {"status": "probe_failed", "version": None}
    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError:
        return {"status": "invalid_output", "version": None}
    match = extractor.search(text)
    if match is None:
        return {"status": "unrecognized_version", "version": None}
    return {"status": "present", "version": match.group(1)}


def probe_artifact_receipt(host_id: str) -> dict[str, object]:
    """Run one fixed, payload-silent installed-artifact receipt command."""

    command = ARTIFACT_RECEIPT_COMMANDS.get(host_id)
    if command is None:
        return {"status": "not_applicable", "receipt": None}
    executable = shutil.which(command[0])
    if executable is None:
        return {"status": "missing", "receipt": None}
    try:
        completed = subprocess.run(  # noqa: S603 -- fixed read-only argv above
            [str(Path(executable).resolve()), *command[1:]],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_version_environment(),
            shell=False,
            check=False,
            timeout=VERSION_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {"status": "probe_failed", "receipt": None}
    output = completed.stdout[: MAX_RECEIPT_OUTPUT_BYTES + 1]
    if len(output) > MAX_RECEIPT_OUTPUT_BYTES:
        return {"status": "oversized_output", "receipt": None}
    if completed.returncode != 0:
        return {"status": "probe_failed", "receipt": None}
    try:
        receipt = json.loads(
            output.decode("utf-8"),
            object_pairs_hook=_pairs_object,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ManifestError):
        return {"status": "invalid_output", "receipt": None}
    if not isinstance(receipt, dict):
        return {"status": "invalid_output", "receipt": None}
    return {"status": "present", "receipt": receipt}


def verify_artifact_receipt(
    binding: Mapping[str, object] | None,
    probe: Mapping[str, object],
) -> dict[str, object]:
    """Compare an installed receipt with one exact reviewed artifact binding."""

    if binding is None:
        return {"status": "not_applicable", "verified": True}
    if probe.get("status") != "present":
        return {"status": str(probe.get("status", "probe_failed")), "verified": False}
    receipt = probe.get("receipt")
    if not isinstance(receipt, Mapping) or set(receipt) != ARTIFACT_RECEIPT_FIELDS:
        return {"status": "receipt_mismatch", "verified": False}
    source_digest = receipt.get("installed_source_sha256")
    expected = {
        "schema_version": binding["receipt_schema"],
        "distribution": binding["distribution"],
        "version": binding["version"],
        "memory_contract": binding["memory_contract"],
        "profile": binding["profile"],
        "scope": binding["scope"],
        "caller": binding["caller"],
        "plaintext_fallback": False,
        "artifact_bound": True,
        "artifact_sha256": binding["sha256"],
        "record_integrity": True,
    }
    if (
        any(receipt.get(key) != value for key, value in expected.items())
        or not isinstance(source_digest, str)
        or HEX_SHA256.fullmatch(source_digest) is None
    ):
        return {"status": "receipt_mismatch", "verified": False}
    return {
        "status": "present",
        "verified": True,
        "artifact_sha256": receipt["artifact_sha256"],
        "installed_source_sha256": source_digest,
    }


def audit_authority(
    root: Path,
    manifest: Mapping[str, object],
    *,
    installed: bool = False,
    version_probe: Callable[[str], Mapping[str, object]] = probe_installed_version,
    artifact_probe: Callable[[str], Mapping[str, object]] = probe_artifact_receipt,
) -> dict[str, Any]:
    """Return a payload-silent source/runtime authority report."""

    normalized = validate_manifest(root, manifest)
    shared_actual = artifact_digest(root, normalized["shared_source_artifacts"])
    shared_current = shared_actual == normalized["shared_source_digest"]
    host_reports: list[dict[str, Any]] = []

    for host in normalized["hosts"]:
        source_actual = artifact_digest(root, host["source_artifacts"])
        host_source_current = source_actual == host["source_digest"]
        source_current = shared_current and host_source_current
        runtime = (
            dict(version_probe(host["id"]))
            if installed
            else {"status": "not_probed", "version": None}
        )
        artifact_runtime = (
            verify_artifact_receipt(
                host["artifact_binding"],
                dict(artifact_probe(host["id"])),
            )
            if installed
            else {
                "status": (
                    "not_probed"
                    if host["artifact_binding"] is not None
                    else "not_applicable"
                ),
                "verified": host["artifact_binding"] is None,
            }
        )
        evidence_state = host["evidence_state"]
        tested_version = host["tested_version"]
        if evidence_state == "blocked":
            authority_status = "blocked"
        elif not source_current:
            authority_status = "source_evidence_stale"
        elif evidence_state == "repository_only":
            authority_status = "repository_only"
        elif evidence_state == "external_unbound":
            authority_status = "external_evidence_unbound"
        elif not installed:
            authority_status = "runtime_not_probed"
        elif runtime.get("status") != "present":
            authority_status = "runtime_unavailable"
        elif runtime.get("version") != tested_version:
            authority_status = "runtime_version_stale"
        elif artifact_runtime.get("verified") is not True:
            authority_status = "runtime_artifact_unverified"
        elif evidence_state == "conditional":
            authority_status = "conditional_boundary_current"
        else:
            authority_status = "qualified_boundary_current"

        host_reports.append(
            {
                "id": host["id"],
                "display_name": host["display_name"],
                "adapter": host["adapter"],
                "authority_status": authority_status,
                "recorded_evidence_state": evidence_state,
                "qualified_boundary": host["qualified_boundary"],
                "tested_on": host["tested_on"],
                "tested_version": tested_version,
                "source_evidence_current": source_current,
                "runtime_probe": runtime,
                "artifact_probe": artifact_runtime,
                "checks": host["checks"],
                "remaining": host["remaining"],
            }
        )

    current = [
        item["id"]
        for item in host_reports
        if item["authority_status"]
        in {"qualified_boundary_current", "conditional_boundary_current"}
    ]
    blocked = [
        item["id"] for item in host_reports if item["authority_status"] == "blocked"
    ]
    not_current = [
        item["id"]
        for item in host_reports
        if item["authority_status"]
        not in {
            "qualified_boundary_current",
            "conditional_boundary_current",
            "blocked",
        }
    ]
    return {
        "schema_version": 1,
        "profile": normalized["profile"],
        "scope": normalized["scope"],
        "claim": (
            "Evidence applies only to each named boundary. Adapter presence and "
            "matching versions do not qualify excluded host modes."
        ),
        "shared_source_evidence_current": shared_current,
        "all_hosts_singular_authority": not blocked and not not_current,
        "current_boundaries": current,
        "blocked_hosts": blocked,
        "not_current_hosts": not_current,
        "hosts": host_reports,
        "limitations": normalized["limitations"],
    }


def _render_text(report: Mapping[str, object]) -> str:
    lines = [
        "Echo Veil host authority evidence",
        f"shared source current: {str(report['shared_source_evidence_current']).lower()}",
        f"all hosts singular authority: {str(report['all_hosts_singular_authority']).lower()}",
    ]
    hosts = report.get("hosts")
    if isinstance(hosts, list):
        for value in hosts:
            if not isinstance(value, Mapping):
                continue
            runtime = value.get("runtime_probe")
            version = runtime.get("version") if isinstance(runtime, Mapping) else None
            suffix = f" ({version})" if isinstance(version, str) else ""
            lines.append(
                f"- {value.get('display_name')}: "
                f"{value.get('authority_status')}{suffix}"
            )
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Verify digest-bound Echo Veil host evidence without treating "
            "installation as proof of a live enforcement gate."
        )
    )
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument(
        "--installed",
        action="store_true",
        help="run fixed read-only version probes for known installed hosts",
    )
    parser.add_argument(
        "--require-current",
        action="append",
        default=[],
        metavar="HOST",
        help=(
            "fail unless this host has current source-bound runtime evidence; "
            "repeat for multiple hosts"
        ),
    )
    parser.add_argument("--text", action="store_true", help="render a compact table")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        manifest = load_manifest(args.manifest)
        report = audit_authority(
            ROOT,
            manifest,
            installed=args.installed or bool(args.require_current),
        )
        known = {
            item["id"]: item
            for item in report["hosts"]
            if isinstance(item, dict) and isinstance(item.get("id"), str)
        }
        failures: list[str] = []
        source_failures = [
            item["id"]
            for item in report["hosts"]
            if isinstance(item, dict)
            and item.get("source_evidence_current") is not True
        ]
        if source_failures:
            report["source_evidence_failures"] = source_failures
            failures.extend(
                f"{host_id}: source_evidence_stale" for host_id in source_failures
            )
        for host_id in args.require_current:
            if host_id not in known:
                failures.append(f"unknown host: {host_id}")
                continue
            if known[host_id]["authority_status"] not in {
                "qualified_boundary_current",
                "conditional_boundary_current",
            }:
                failures.append(f"{host_id}: {known[host_id]['authority_status']}")
        if failures:
            report["gate_failures"] = failures
        print(
            _render_text(report)
            if args.text
            else json.dumps(report, sort_keys=True, separators=(",", ":"))
        )
        return 2 if failures else 0
    except (ManifestError, OSError) as exc:
        print(
            json.dumps(
                {
                    "error": "authority_evidence_invalid",
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
