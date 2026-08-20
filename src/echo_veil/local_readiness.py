"""Fail-closed readiness contract for trusted local Echo Veil deployments.

This module deliberately does not grant preflight or mutation authority.  It
turns already-verified runtime evidence into the optional ``capabilities_v1``
operator surface while keeping the signed preflight-v2 contract unchanged.

``local_production_ready`` describes a host-trusted boundary.  It must never be
read as hardware isolation, remote attestation, or protection from compromise
of the host account or process.
"""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

CAPABILITIES_SCHEMA = "echo-veil-capabilities-v1"
LOCAL_STAGING_MODE = "local-staging"
LOCAL_PRODUCTION_MODE = "local-production"
LEGACY_MIGRATION_MODE = "legacy-migration-only"
OFFLINE_READ_ONLY_MODE = "offline-read-only"

_DEPLOYMENT_MODES = frozenset(
    {
        LOCAL_STAGING_MODE,
        LOCAL_PRODUCTION_MODE,
        LEGACY_MIGRATION_MODE,
        OFFLINE_READ_ONLY_MODE,
    }
)
_ROLLBACK_TIERS = frozenset({"none", "local-best-effort", "external-monotonic"})
_KEY_CUSTODY_PATTERN = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
QUALIFIED_LOCAL_KEY_CUSTODY = frozenset({"macos-secure-enclave-v1"})

# Codes are stable machine identifiers.  Human guidance lives here rather than
# in signed or host-parsed preflight structures.
REMEDIATIONS: dict[str, str] = {
    "EV-LOCAL-MODE-NOT-CONFIGURED": (
        "Complete the guided local-production setup and explicitly select "
        "local-production mode."
    ),
    "EV-IMPLEMENTATION-UNHEALTHY": (
        "Repair lifecycle, persistence, or retrieval health before qualifying "
        "the profile."
    ),
    "EV-AT-REST-UNPROTECTED": (
        "Migrate every payload, vector, semantic contract, and index record to "
        "scoped authenticated encryption."
    ),
    "EV-PROTECTED-STATE-INCOMPLETE": (
        "Reconcile every payload with its protected lifecycle and semantic-index state."
    ),
    "EV-EMBEDDING-IDENTITY-UNVERIFIED": (
        "Use digest-bound qwen3-embedding and re-open the matching profile."
    ),
    "EV-PROFILE-ACCESS-UNVERIFIED": (
        "Repair profile ownership and owner-only access controls."
    ),
    "EV-ARTIFACT-UNVERIFIED": (
        "Install and verify an immutable Echo Veil artifact receipt."
    ),
    "EV-BACKUP-UNVERIFIED": ("Create and authenticate a writer-locked profile backup."),
    "EV-RESTORE-UNVERIFIED": (
        "Complete an actual restore drill and verify exact logical counts."
    ),
    "EV-HOST-BOUNDARY-UNVERIFIED": (
        "Run through a qualified host boundary with a matching artifact receipt."
    ),
    "EV-KEY-CUSTODY-UNQUALIFIED": (
        "Migrate the profile root to the reviewed Secure Enclave custody provider."
    ),
    "EV-READINESS-EVIDENCE-INVALID": (
        "Verify the latest backup and repeat the restore drill; authenticated "
        "local-readiness evidence is missing or corrupt."
    ),
    "EV-RECONCILIATION-PENDING": (
        "Finish the protected reconciliation backlog before retrying readiness."
    ),
    "EV-QUARANTINE-NONEMPTY": (
        "Review and repair or explicitly remove every quarantined record."
    ),
    "EV-PLAINTEXT-FALLBACK": (
        "Investigate the plaintext fallback attempt and rebuild from verified "
        "protected state."
    ),
    "EV-KEY-MIGRATION-INCOMPLETE": (
        "Complete and verify the active key migration before qualification."
    ),
    "EV-MODEL-UNAVAILABLE": (
        "Restore the digest-matched local embedding model before qualification."
    ),
}


def _strict_bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise TypeError(f"{label} must be a boolean")
    return value


def _non_negative_count(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise TypeError(f"{label} must be a non-negative integer")
    return value


@dataclass(frozen=True, slots=True)
class LocalReadinessEvidence:
    """Evidence supplied by independently verified local subsystems.

    The default is intentionally unqualified.  Environment strings and RPC
    input are never converted into positive evidence by this module.
    """

    artifact_verified: bool = False
    backup_verified: bool = False
    restore_verified: bool = False
    host_boundary_verified: bool = False
    key_custody: str = "file-v1"
    rollback_detection: str = "none"

    def __post_init__(self) -> None:
        for name in (
            "artifact_verified",
            "backup_verified",
            "restore_verified",
            "host_boundary_verified",
        ):
            _strict_bool(getattr(self, name), name)
        if (
            not isinstance(self.key_custody, str)
            or _KEY_CUSTODY_PATTERN.fullmatch(self.key_custody) is None
        ):
            raise ValueError("key_custody is invalid")
        if self.rollback_detection not in _ROLLBACK_TIERS:
            raise ValueError("rollback_detection is invalid")


@dataclass(frozen=True, slots=True)
class LocalReadinessState:
    """Observed state used to calculate the local-production gate."""

    configured_mode: str
    implementation_healthy: bool
    at_rest_encrypted: bool
    protected_semantic_state: bool
    embedding_identity_verified: bool
    profile_access_verified: bool
    reconciliation_backlog: int
    quarantined_records: int
    plaintext_fallback_attempts: int
    key_migration_complete: bool
    model_available: bool
    evidence: LocalReadinessEvidence = LocalReadinessEvidence()
    enclave_production_ready: bool = False
    hardware_isolated: bool = False
    remotely_attested: bool = False
    host_compromise_protected: bool = False

    def __post_init__(self) -> None:
        if self.configured_mode not in _DEPLOYMENT_MODES:
            raise ValueError("configured_mode is invalid")
        for name in (
            "implementation_healthy",
            "at_rest_encrypted",
            "protected_semantic_state",
            "embedding_identity_verified",
            "profile_access_verified",
            "key_migration_complete",
            "model_available",
            "enclave_production_ready",
            "hardware_isolated",
            "remotely_attested",
            "host_compromise_protected",
        ):
            _strict_bool(getattr(self, name), name)
        for name in (
            "reconciliation_backlog",
            "quarantined_records",
            "plaintext_fallback_attempts",
        ):
            _non_negative_count(getattr(self, name), name)
        if not isinstance(self.evidence, LocalReadinessEvidence):
            raise TypeError("evidence must be LocalReadinessEvidence")


def _readiness_failures(state: LocalReadinessState) -> list[str]:
    failures: list[str] = []
    checks = (
        (
            state.configured_mode == LOCAL_PRODUCTION_MODE,
            "EV-LOCAL-MODE-NOT-CONFIGURED",
        ),
        (state.implementation_healthy, "EV-IMPLEMENTATION-UNHEALTHY"),
        (state.at_rest_encrypted, "EV-AT-REST-UNPROTECTED"),
        (state.protected_semantic_state, "EV-PROTECTED-STATE-INCOMPLETE"),
        (
            state.embedding_identity_verified,
            "EV-EMBEDDING-IDENTITY-UNVERIFIED",
        ),
        (state.profile_access_verified, "EV-PROFILE-ACCESS-UNVERIFIED"),
        (state.evidence.artifact_verified, "EV-ARTIFACT-UNVERIFIED"),
        (state.evidence.backup_verified, "EV-BACKUP-UNVERIFIED"),
        (state.evidence.restore_verified, "EV-RESTORE-UNVERIFIED"),
        (
            state.evidence.host_boundary_verified,
            "EV-HOST-BOUNDARY-UNVERIFIED",
        ),
        (
            state.evidence.key_custody in QUALIFIED_LOCAL_KEY_CUSTODY,
            "EV-KEY-CUSTODY-UNQUALIFIED",
        ),
        (state.reconciliation_backlog == 0, "EV-RECONCILIATION-PENDING"),
        (state.quarantined_records == 0, "EV-QUARANTINE-NONEMPTY"),
        (state.plaintext_fallback_attempts == 0, "EV-PLAINTEXT-FALLBACK"),
        (state.key_migration_complete, "EV-KEY-MIGRATION-INCOMPLETE"),
        (state.model_available, "EV-MODEL-UNAVAILABLE"),
    )
    for passed, code in checks:
        if not passed:
            failures.append(code)
    return failures


def build_capabilities_v1(state: LocalReadinessState) -> dict[str, Any]:
    """Build and self-validate the unsigned, diagnostic readiness surface."""

    if not isinstance(state, LocalReadinessState):
        raise TypeError("state must be LocalReadinessState")
    failures = _readiness_failures(state)
    local_ready = not failures
    enclave_ready = (
        state.enclave_production_ready
        and state.implementation_healthy
        and state.at_rest_encrypted
        and state.protected_semantic_state
        and state.embedding_identity_verified
        and state.profile_access_verified
        and state.evidence.artifact_verified
        and state.evidence.backup_verified
        and state.evidence.restore_verified
        and state.evidence.host_boundary_verified
        and state.reconciliation_backlog == 0
        and state.quarantined_records == 0
        and state.plaintext_fallback_attempts == 0
        and state.key_migration_complete
        and state.model_available
        and state.hardware_isolated
        and state.remotely_attested
        and state.host_compromise_protected
    )
    if enclave_ready:
        protection_tier = "attested-enclave"
        runtime_exposure = "attested-enclave-boundary"
    elif local_ready:
        protection_tier = "host-trusted-local"
        runtime_exposure = "transient-process-memory"
    else:
        protection_tier = (
            "local-production-blocked"
            if state.configured_mode == LOCAL_PRODUCTION_MODE
            else state.configured_mode
        )
        runtime_exposure = "transient-process-memory"

    limitations = []
    if not state.hardware_isolated:
        limitations.append("No hardware-isolated execution boundary is active.")
    if not state.remotely_attested:
        limitations.append("No remote attestation is active.")
    if not state.host_compromise_protected:
        limitations.append(
            "A compromised host account or process can access runtime plaintext."
        )

    report: dict[str, Any] = {
        "schema": CAPABILITIES_SCHEMA,
        "implementation_healthy": state.implementation_healthy,
        "local_production_ready": local_ready,
        "production_ready": enclave_ready,
        "protection_tier": protection_tier,
        "at_rest_encrypted": state.at_rest_encrypted,
        "runtime_plaintext_exposure": runtime_exposure,
        "hardware_isolated": state.hardware_isolated,
        "remotely_attested": state.remotely_attested,
        "host_compromise_protected": state.host_compromise_protected,
        "artifact_verified": state.evidence.artifact_verified,
        "backup_verified": state.evidence.backup_verified,
        "restore_verified": state.evidence.restore_verified,
        "rollback_detection": state.evidence.rollback_detection,
        "host_boundary_verified": state.evidence.host_boundary_verified,
        "key_custody": state.evidence.key_custody,
        "embedding_identity_verified": state.embedding_identity_verified,
        "remediation_codes": failures,
        "limitations": limitations,
    }
    # Import lazily because the receipt compatibility module intentionally
    # imports legacy key helpers from agent_memory during package startup.
    from .protocol_compat import parse_capabilities_v1

    parsed = parse_capabilities_v1(report)
    if parsed is None:  # pragma: no cover - parser contract excludes this branch
        raise AssertionError("capabilities_v1 parser rejected a generated report")
    return parsed


def remediation_messages(codes: list[str]) -> dict[str, str]:
    """Return path- and payload-free operator guidance for known codes."""

    if not isinstance(codes, list) or any(not isinstance(code, str) for code in codes):
        raise TypeError("remediation codes must be a list of strings")
    unknown = [code for code in codes if code not in REMEDIATIONS]
    if unknown:
        raise ValueError("unknown readiness remediation code")
    return {code: REMEDIATIONS[code] for code in codes}


__all__ = [
    "LEGACY_MIGRATION_MODE",
    "LOCAL_PRODUCTION_MODE",
    "LOCAL_STAGING_MODE",
    "OFFLINE_READ_ONLY_MODE",
    "QUALIFIED_LOCAL_KEY_CUSTODY",
    "REMEDIATIONS",
    "LocalReadinessEvidence",
    "LocalReadinessState",
    "build_capabilities_v1",
    "remediation_messages",
]
