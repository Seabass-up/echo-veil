"""Path-free local artifact and host-boundary qualification receipts.

These receipts are inputs only after fixed verifiers have completed. They do
not alter preflight-v2 and are never accepted from an agent RPC, environment
variable, or unsigned capability response.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import json
import re
import sysconfig
import time
from pathlib import Path

from .codex_artifact import (
    CodexArtifactError,
    _console_interpreter,
    _verify_echo_wheel,
)

INSTALLED_ARTIFACT_SCHEMA = "echo-veil-installed-artifact-v1"
HOST_BOUNDARY_SCHEMA = "echo-veil-host-boundary-v1"
HOST_QUALIFICATION_SCHEMA = "echo-veil-host-qualification-v1"
INSTALLED_ARTIFACT_DOMAIN = b"echo-veil-installed-artifact-v1\0"
HOST_BOUNDARY_DOMAIN = b"echo-veil-host-boundary-v1\0"
MAX_HOST_QUALIFICATION_SECONDS = 7 * 24 * 60 * 60

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_HOST_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
_BOUNDARY_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
_SCOPE_ID = re.compile(r"scope-[0-9a-f]{32}\Z")
_VERSION = re.compile(r"[0-9A-Za-z][0-9A-Za-z.+_-]{0,127}\Z")


class LocalAuthorityError(RuntimeError):
    """Installed artifact or host-boundary evidence is invalid or stale."""


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise LocalAuthorityError(f"{label} is invalid")
    return value


def _integer(value: object, label: str, *, positive: bool = False) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise LocalAuthorityError(f"{label} is invalid")
    if value < (1 if positive else 0):
        raise LocalAuthorityError(f"{label} is invalid")
    return value


@dataclass(frozen=True, slots=True)
class VerifiedInstalledArtifact:
    """One current, path-free Echo wheel/install verification result."""

    authority_id: str
    wheel_sha256: str
    installed_source_sha256: str
    version: str
    installed_files_verified: int
    agent_console_body_sha256: str
    hook_console_body_sha256: str
    runner_console_body_sha256: str
    verified_at: int

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "wheel_sha256",
            "installed_source_sha256",
            "agent_console_body_sha256",
            "hook_console_body_sha256",
            "runner_console_body_sha256",
        ):
            _digest(getattr(self, name), name)
        if (
            not isinstance(self.version, str)
            or _VERSION.fullmatch(self.version) is None
        ):
            raise LocalAuthorityError("artifact version is invalid")
        _integer(
            self.installed_files_verified,
            "installed file count",
            positive=True,
        )
        _integer(self.verified_at, "artifact verification time")

    def stable_claims(self) -> dict[str, object]:
        return {
            "agent_console_body_sha256": self.agent_console_body_sha256,
            "distribution": "echo-veil",
            "hook_console_body_sha256": self.hook_console_body_sha256,
            "installed_files_verified": self.installed_files_verified,
            "installed_source_sha256": self.installed_source_sha256,
            "runner_console_body_sha256": self.runner_console_body_sha256,
            "schema": INSTALLED_ARTIFACT_SCHEMA,
            "version": self.version,
            "wheel_sha256": self.wheel_sha256,
        }

    def as_record(self) -> dict[str, object]:
        return {
            "authority_id": self.authority_id,
            **self.stable_claims(),
            "verified_at": self.verified_at,
        }


def verify_echo_artifact(
    *,
    agent_executable: Path,
    hook_executable: Path,
    runner_executable: Path,
    verified_at: int | None = None,
) -> VerifiedInstalledArtifact:
    """Verify one non-editable wheel installation and all Echo entrypoints."""

    try:
        details = _verify_echo_wheel(agent_executable, hook_executable)
        agent_interpreter, _agent_body = _console_interpreter(agent_executable)
        hook_interpreter, _hook_body = _console_interpreter(hook_executable)
        runner_interpreter, runner_body = _console_interpreter(runner_executable)
    except (CodexArtifactError, OSError) as exc:
        raise LocalAuthorityError(
            "installed Echo artifact verification failed"
        ) from exc
    if not (agent_interpreter == hook_interpreter == runner_interpreter):
        raise LocalAuthorityError("Echo entrypoints use different environments")
    claims = {
        "agent_console_body_sha256": _digest(
            details.get("agent_console_body_sha256"),
            "agent console digest",
        ),
        "distribution": "echo-veil",
        "hook_console_body_sha256": _digest(
            details.get("hook_console_body_sha256"),
            "hook console digest",
        ),
        "installed_files_verified": _integer(
            details.get("installed_files_verified"),
            "installed file count",
            positive=True,
        ),
        "installed_source_sha256": _digest(
            details.get("installed_source_sha256"),
            "installed source digest",
        ),
        "runner_console_body_sha256": (
            "sha256:" + hashlib.sha256(runner_body).hexdigest()
        ),
        "schema": INSTALLED_ARTIFACT_SCHEMA,
        "version": details.get("version"),
        "wheel_sha256": _digest(
            details.get("wheel_sha256"),
            "wheel digest",
        ),
    }
    version = claims["version"]
    if not isinstance(version, str) or _VERSION.fullmatch(version) is None:
        raise LocalAuthorityError("artifact version is invalid")
    authority_id = (
        "sha256:"
        + hashlib.sha256(INSTALLED_ARTIFACT_DOMAIN + _canonical(claims)).hexdigest()
    )
    now = int(time.time()) if verified_at is None else verified_at
    return VerifiedInstalledArtifact(
        authority_id=authority_id,
        wheel_sha256=str(claims["wheel_sha256"]),
        installed_source_sha256=str(claims["installed_source_sha256"]),
        version=version,
        installed_files_verified=_integer(
            claims["installed_files_verified"],
            "installed file count",
            positive=True,
        ),
        agent_console_body_sha256=str(claims["agent_console_body_sha256"]),
        hook_console_body_sha256=str(claims["hook_console_body_sha256"]),
        runner_console_body_sha256=str(claims["runner_console_body_sha256"]),
        verified_at=now,
    )


def verify_current_echo_artifact() -> VerifiedInstalledArtifact:
    """Discover and verify the Echo installation owning this interpreter."""

    raw_scripts = sysconfig.get_path("scripts")
    if not isinstance(raw_scripts, str) or not raw_scripts:
        raise LocalAuthorityError("Python scripts directory is unavailable")
    scripts = Path(raw_scripts).absolute()
    return verify_echo_artifact(
        agent_executable=scripts / "echo-veil-agent",
        hook_executable=scripts / "echo-veil-preflight-hook",
        runner_executable=scripts / "echo-veil-shielded-run",
    )


def parse_artifact_record(value: object) -> VerifiedInstalledArtifact:
    expected = {
        "agent_console_body_sha256",
        "authority_id",
        "distribution",
        "hook_console_body_sha256",
        "installed_files_verified",
        "installed_source_sha256",
        "runner_console_body_sha256",
        "schema",
        "verified_at",
        "version",
        "wheel_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise LocalAuthorityError("artifact receipt fields are invalid")
    if (
        value.get("schema") != INSTALLED_ARTIFACT_SCHEMA
        or value.get("distribution") != "echo-veil"
    ):
        raise LocalAuthorityError("artifact receipt schema is invalid")
    version = value.get("version")
    if not isinstance(version, str):
        raise LocalAuthorityError("artifact version is invalid")
    receipt = VerifiedInstalledArtifact(
        authority_id=_digest(value.get("authority_id"), "artifact authority ID"),
        wheel_sha256=_digest(value.get("wheel_sha256"), "wheel digest"),
        installed_source_sha256=_digest(
            value.get("installed_source_sha256"),
            "installed source digest",
        ),
        version=version,
        installed_files_verified=_integer(
            value.get("installed_files_verified"),
            "installed file count",
            positive=True,
        ),
        agent_console_body_sha256=_digest(
            value.get("agent_console_body_sha256"),
            "agent console digest",
        ),
        hook_console_body_sha256=_digest(
            value.get("hook_console_body_sha256"),
            "hook console digest",
        ),
        runner_console_body_sha256=_digest(
            value.get("runner_console_body_sha256"),
            "runner console digest",
        ),
        verified_at=_integer(value.get("verified_at"), "artifact verification time"),
    )
    calculated = (
        "sha256:"
        + hashlib.sha256(
            INSTALLED_ARTIFACT_DOMAIN + _canonical(receipt.stable_claims())
        ).hexdigest()
    )
    if not hmac.compare_digest(calculated, receipt.authority_id):
        raise LocalAuthorityError("artifact receipt authority is invalid")
    return receipt


def artifact_record_is_current(value: object) -> bool:
    """Rehash the active installation and compare it with stored evidence."""

    try:
        stored = parse_artifact_record(value)
        current = verify_current_echo_artifact()
    except LocalAuthorityError:
        return False
    return hmac.compare_digest(stored.authority_id, current.authority_id)


@dataclass(frozen=True, slots=True)
class HostQualificationEvidence:
    """Bounded output of a fixed installed-host healthy/outage verifier."""

    host_id: str
    boundary: str
    host_artifact_authority_id: str
    healthy_preflight_v2: bool
    healthy_receipt_verified: bool
    outage_blocked: bool
    outage_provider_calls: int
    outage_model_calls: int
    outage_agent_starts: int
    outage_tool_calls: int
    competing_mutable_memory: bool

    def __post_init__(self) -> None:
        if _HOST_ID.fullmatch(self.host_id) is None:
            raise LocalAuthorityError("host ID is invalid")
        if _BOUNDARY_ID.fullmatch(self.boundary) is None:
            raise LocalAuthorityError("host boundary ID is invalid")
        _digest(self.host_artifact_authority_id, "host artifact authority ID")
        for name in (
            "healthy_preflight_v2",
            "healthy_receipt_verified",
            "outage_blocked",
            "competing_mutable_memory",
        ):
            if not isinstance(getattr(self, name), bool):
                raise LocalAuthorityError(f"{name} is invalid")
        for name in (
            "outage_provider_calls",
            "outage_model_calls",
            "outage_agent_starts",
            "outage_tool_calls",
        ):
            _integer(getattr(self, name), name)

    def as_claims(self) -> dict[str, object]:
        return {
            "boundary": self.boundary,
            "competing_mutable_memory": self.competing_mutable_memory,
            "healthy_preflight_v2": self.healthy_preflight_v2,
            "healthy_receipt_verified": self.healthy_receipt_verified,
            "host_artifact_authority_id": self.host_artifact_authority_id,
            "host_id": self.host_id,
            "outage_agent_starts": self.outage_agent_starts,
            "outage_blocked": self.outage_blocked,
            "outage_model_calls": self.outage_model_calls,
            "outage_provider_calls": self.outage_provider_calls,
            "outage_tool_calls": self.outage_tool_calls,
            "schema": HOST_QUALIFICATION_SCHEMA,
        }


@dataclass(frozen=True, slots=True)
class VerifiedHostBoundary:
    authority_id: str
    host_id: str
    boundary: str
    host_artifact_authority_id: str
    echo_artifact_authority_id: str
    preflight_authority_id: str
    profile_hash: str
    scope_id: str
    qualification_digest: str
    verified_at: int
    expires_at: int

    def __post_init__(self) -> None:
        for name in (
            "authority_id",
            "host_artifact_authority_id",
            "echo_artifact_authority_id",
            "preflight_authority_id",
            "profile_hash",
            "qualification_digest",
        ):
            _digest(getattr(self, name), name)
        if _HOST_ID.fullmatch(self.host_id) is None:
            raise LocalAuthorityError("host ID is invalid")
        if _BOUNDARY_ID.fullmatch(self.boundary) is None:
            raise LocalAuthorityError("host boundary ID is invalid")
        if _SCOPE_ID.fullmatch(self.scope_id) is None:
            raise LocalAuthorityError("host scope ID is invalid")
        verified = _integer(self.verified_at, "host verification time")
        expires = _integer(self.expires_at, "host evidence expiry", positive=True)
        if not verified < expires <= verified + MAX_HOST_QUALIFICATION_SECONDS:
            raise LocalAuthorityError("host evidence lifetime is invalid")

    def stable_claims(self) -> dict[str, object]:
        return {
            "boundary": self.boundary,
            "echo_artifact_authority_id": self.echo_artifact_authority_id,
            "expires_at": self.expires_at,
            "host_artifact_authority_id": self.host_artifact_authority_id,
            "host_id": self.host_id,
            "preflight_authority_id": self.preflight_authority_id,
            "profile_hash": self.profile_hash,
            "qualification_digest": self.qualification_digest,
            "schema": HOST_BOUNDARY_SCHEMA,
            "scope_id": self.scope_id,
            "verified_at": self.verified_at,
        }

    def as_record(self) -> dict[str, object]:
        return {"authority_id": self.authority_id, **self.stable_claims()}


def verify_host_qualification(
    evidence: HostQualificationEvidence,
    *,
    echo_artifact_authority_id: str,
    preflight_authority_id: str,
    profile_hash: str,
    scope_id: str,
    verified_at: int | None = None,
    lifetime_seconds: int = 24 * 60 * 60,
) -> VerifiedHostBoundary:
    """Turn a fixed verifier result into one short-lived bound receipt."""

    if not isinstance(evidence, HostQualificationEvidence):
        raise TypeError("host qualification evidence is required")
    if not (
        evidence.healthy_preflight_v2
        and evidence.healthy_receipt_verified
        and evidence.outage_blocked
        and evidence.outage_provider_calls == 0
        and evidence.outage_model_calls == 0
        and evidence.outage_agent_starts == 0
        and evidence.outage_tool_calls == 0
        and not evidence.competing_mutable_memory
    ):
        raise LocalAuthorityError("host qualification did not prove a hard boundary")
    echo_id = _digest(echo_artifact_authority_id, "Echo artifact authority ID")
    preflight_id = _digest(preflight_authority_id, "preflight authority ID")
    profile = _digest(profile_hash, "profile hash")
    if _SCOPE_ID.fullmatch(scope_id) is None:
        raise LocalAuthorityError("host scope ID is invalid")
    if (
        isinstance(lifetime_seconds, bool)
        or not isinstance(lifetime_seconds, int)
        or not 1 <= lifetime_seconds <= MAX_HOST_QUALIFICATION_SECONDS
    ):
        raise LocalAuthorityError("host qualification lifetime is invalid")
    now = int(time.time()) if verified_at is None else verified_at
    qualification_digest = (
        "sha256:" + hashlib.sha256(_canonical(evidence.as_claims())).hexdigest()
    )
    claims = {
        "boundary": evidence.boundary,
        "echo_artifact_authority_id": echo_id,
        "expires_at": now + lifetime_seconds,
        "host_artifact_authority_id": evidence.host_artifact_authority_id,
        "host_id": evidence.host_id,
        "preflight_authority_id": preflight_id,
        "profile_hash": profile,
        "qualification_digest": qualification_digest,
        "schema": HOST_BOUNDARY_SCHEMA,
        "scope_id": scope_id,
        "verified_at": now,
    }
    authority_id = (
        "sha256:"
        + hashlib.sha256(HOST_BOUNDARY_DOMAIN + _canonical(claims)).hexdigest()
    )
    return VerifiedHostBoundary(
        authority_id=authority_id,
        host_id=evidence.host_id,
        boundary=evidence.boundary,
        host_artifact_authority_id=evidence.host_artifact_authority_id,
        echo_artifact_authority_id=echo_id,
        preflight_authority_id=preflight_id,
        profile_hash=profile,
        scope_id=scope_id,
        qualification_digest=qualification_digest,
        verified_at=now,
        expires_at=now + lifetime_seconds,
    )


def parse_host_boundary_record(value: object) -> VerifiedHostBoundary:
    expected = {
        "authority_id",
        "boundary",
        "echo_artifact_authority_id",
        "expires_at",
        "host_artifact_authority_id",
        "host_id",
        "preflight_authority_id",
        "profile_hash",
        "qualification_digest",
        "schema",
        "scope_id",
        "verified_at",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise LocalAuthorityError("host-boundary receipt fields are invalid")
    if value.get("schema") != HOST_BOUNDARY_SCHEMA:
        raise LocalAuthorityError("host-boundary receipt schema is invalid")
    receipt = VerifiedHostBoundary(
        authority_id=_digest(value.get("authority_id"), "host authority ID"),
        host_id=str(value.get("host_id")),
        boundary=str(value.get("boundary")),
        host_artifact_authority_id=_digest(
            value.get("host_artifact_authority_id"),
            "host artifact authority ID",
        ),
        echo_artifact_authority_id=_digest(
            value.get("echo_artifact_authority_id"),
            "Echo artifact authority ID",
        ),
        preflight_authority_id=_digest(
            value.get("preflight_authority_id"),
            "preflight authority ID",
        ),
        profile_hash=_digest(value.get("profile_hash"), "profile hash"),
        scope_id=str(value.get("scope_id")),
        qualification_digest=_digest(
            value.get("qualification_digest"),
            "qualification digest",
        ),
        verified_at=_integer(value.get("verified_at"), "host verification time"),
        expires_at=_integer(
            value.get("expires_at"),
            "host evidence expiry",
            positive=True,
        ),
    )
    calculated = (
        "sha256:"
        + hashlib.sha256(
            HOST_BOUNDARY_DOMAIN + _canonical(receipt.stable_claims())
        ).hexdigest()
    )
    if not hmac.compare_digest(calculated, receipt.authority_id):
        raise LocalAuthorityError("host-boundary authority is invalid")
    return receipt


def host_boundary_record_is_current(
    value: object,
    *,
    echo_artifact_authority_id: str,
    preflight_authority_id: str,
    profile_hash: str,
    scope_id: str,
    now: int | None = None,
) -> bool:
    try:
        receipt = parse_host_boundary_record(value)
        expected_echo = _digest(
            echo_artifact_authority_id,
            "Echo artifact authority ID",
        )
        expected_preflight = _digest(
            preflight_authority_id,
            "preflight authority ID",
        )
        expected_profile = _digest(profile_hash, "profile hash")
    except LocalAuthorityError:
        return False
    current = int(time.time()) if now is None else now
    return (
        receipt.verified_at <= current < receipt.expires_at
        and hmac.compare_digest(receipt.echo_artifact_authority_id, expected_echo)
        and hmac.compare_digest(receipt.preflight_authority_id, expected_preflight)
        and hmac.compare_digest(receipt.profile_hash, expected_profile)
        and hmac.compare_digest(receipt.scope_id, scope_id)
    )


__all__ = [
    "HOST_BOUNDARY_SCHEMA",
    "HOST_QUALIFICATION_SCHEMA",
    "INSTALLED_ARTIFACT_SCHEMA",
    "HostQualificationEvidence",
    "LocalAuthorityError",
    "VerifiedHostBoundary",
    "VerifiedInstalledArtifact",
    "artifact_record_is_current",
    "host_boundary_record_is_current",
    "parse_artifact_record",
    "parse_host_boundary_record",
    "verify_current_echo_artifact",
    "verify_echo_artifact",
    "verify_host_qualification",
]
