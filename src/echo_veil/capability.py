"""Capability and doctor reporting for Echo Veil.

The report is intentionally diagnostic only. It does not change runtime behavior
or imply unavailable security features are present. Host applications can use it
to detect development-only backends, missing persistence, non-thread-safe
reference storage, and crypto readiness before integrating Echo Veil.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any

from .crypto_shield import (
    AesGcmCryptoShield,
    EnclaveCryptoShield,
    NullCryptoShield,
    is_crypto_shield,
)


class CapabilityStatus(str, Enum):
    READY = "ready"
    DEGRADED = "degraded"
    BLOCKED = "blocked"


@dataclass(frozen=True)
class CapabilityCheck:
    name: str
    status: CapabilityStatus
    message: str
    recommendation: str = ""
    known_limitations: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        return data


@dataclass(frozen=True)
class CapabilityReport:
    environment: str
    overall_status: CapabilityStatus
    crypto_readiness: CapabilityCheck
    storage_backend: CapabilityCheck
    vector_index_backend: CapabilityCheck
    persistence: CapabilityCheck
    thread_safety: CapabilityCheck
    confidence_gating: CapabilityCheck
    production_blockers: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()
    known_limitations: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict[str, Any]:
        return {
            "environment": self.environment,
            "overall_status": self.overall_status.value,
            "crypto_readiness": self.crypto_readiness.as_dict(),
            "storage_backend": self.storage_backend.as_dict(),
            "vector_index_backend": self.vector_index_backend.as_dict(),
            "persistence": self.persistence.as_dict(),
            "thread_safety": self.thread_safety.as_dict(),
            "confidence_gating": self.confidence_gating.as_dict(),
            "production_blockers": list(self.production_blockers),
            "warnings": list(self.warnings),
            "known_limitations": list(self.known_limitations),
        }


def build_capability_report(oracle: Any) -> CapabilityReport:
    environment = str(getattr(oracle, "environment", "development"))
    blockers: list[str] = []
    warnings: list[str] = []

    shield = getattr(oracle, "shield", None)
    shield_name = type(shield).__name__ if shield is not None else "None"
    if shield is not None and not is_crypto_shield(shield):
        crypto = CapabilityCheck(
            "crypto_readiness",
            CapabilityStatus.BLOCKED,
            f"{shield_name} does not implement the CryptoShield contract.",
            "Provide an object with protect(anchor) and similarity(intent, protected_anchor).",
            ("Invalid shield objects are rejected by Oracle construction.",),
        )
        blockers.append("Configured shield does not implement CryptoShield.")
    elif isinstance(shield, NullCryptoShield) or shield is None:
        crypto = CapabilityCheck(
            "crypto_readiness",
            CapabilityStatus.DEGRADED,
            f"{shield_name} is development-only and provides no confidentiality.",
            "Provide a real CryptoShield before production use.",
            ("Configure EnclaveCryptoShield for the Level-5 security profile.",),
        )
        blockers.append("NullCryptoShield is not production-ready.")
    elif isinstance(shield, EnclaveCryptoShield):
        attestation = shield.attestation
        crypto = CapabilityCheck(
            "crypto_readiness",
            CapabilityStatus.READY,
            "Attested CKKS enclave shield active with a verified ZKP access gate.",
            "Monitor attestation expiry and rotate the enclave sealing key under deployment policy.",
            (
                f"Trust is rooted in the configured verifier for measurement {attestation.measurement}.",
            ),
        )
    elif isinstance(shield, AesGcmCryptoShield):
        crypto = CapabilityCheck(
            "crypto_readiness",
            CapabilityStatus.READY,
            "AES-GCM shield active: anchor vectors are encrypted and authenticated while protected.",
            "Keep the AES key in a secret manager or ECHO_VEIL_CRYPTO_KEY; rotate it under an application-level migration plan.",
            (
                "AES-GCM is not homomorphic; vectors decrypt transiently during similarity().",
                "This does not provide hardware-enclave isolation or zk attestation.",
            ),
        )
    else:
        crypto = CapabilityCheck(
            "crypto_readiness",
            CapabilityStatus.DEGRADED,
            f"Custom shield detected: {shield_name}.",
            "Echo Veil can use this shield structurally, but production readiness requires an external threat-model review.",
            (
                "Custom shield payload serialization and plaintext-retention behavior are implementation-specific.",
                "Capability report cannot prove custom cryptographic strength.",
            ),
        )
        blockers.append(
            "Custom CryptoShield requires external validation before production use."
        )

    archive = getattr(oracle, "archive", None)
    archive_name = str(getattr(archive, "backend_name", type(archive).__name__))
    archive_durable = getattr(archive, "durable", False) is True
    archive_cross_process = getattr(archive, "cross_process_safe", False) is True
    storage = CapabilityCheck(
        "storage_backend",
        CapabilityStatus.READY if archive_durable else CapabilityStatus.DEGRADED,
        (
            f"{archive_name} is durable and restart-safe."
            if archive_durable
            else f"{archive_name} is non-durable/reference storage."
        ),
        (
            "Protect database files and backups with deployment access controls."
            if archive_durable
            else "Configure a durable transactional L3 backend."
        ),
        (
            ()
            if archive_durable
            else ("Archived payloads are lost on process restart.",)
        ),
    )
    if not archive_durable:
        blockers.append("L3 archive is not durable.")

    index = getattr(oracle, "index", None)
    index_name = str(getattr(index, "backend_name", type(index).__name__))
    index_durable = getattr(index, "durable", False) is True
    search_strategy = str(getattr(index, "search_strategy", "unknown"))
    search_is_linear = search_strategy == "linear"
    if index_durable and not search_is_linear:
        index_status = CapabilityStatus.READY
    else:
        index_status = CapabilityStatus.DEGRADED
    vector_index = CapabilityCheck(
        "vector_index_backend",
        index_status,
        (
            f"{index_name} is durable; search strategy is {search_strategy}."
            if index_durable
            else f"{index_name} is non-durable; search strategy is {search_strategy}."
        ),
        (
            "Use an ANN backend when corpus size requires a bounded lookup SLA."
            if search_is_linear
            else "Validate latency and recall against the deployment corpus."
        ),
        (
            ("Linear search has no <5ms global lookup guarantee at large scale.",)
            if search_is_linear
            else ()
        ),
    )
    if not index_durable:
        blockers.append("L2 metadata index is not durable.")
    elif search_is_linear:
        warnings.append("The durable L2 index uses linear search, not ANN lookup.")

    coordinator = getattr(oracle, "storage", None)
    coordinated_transactions = (
        coordinator is not None
        and getattr(coordinator, "durable", False) is True
        and getattr(coordinator, "transactional", False) is True
        and getattr(coordinator, "cross_process_safe", False) is True
        and archive_durable
        and index_durable
    )
    persistence = CapabilityCheck(
        "persistence",
        (
            CapabilityStatus.READY
            if coordinated_transactions
            else CapabilityStatus.BLOCKED
        ),
        (
            "L1 checkpoints and L2/L3 writes are durable, atomic, crash-recoverable, and coordinated across processes."
            if coordinated_transactions
            else "No durable transaction coordinator spans the L2 index and L3 archive."
        ),
        (
            "Back up and test restore procedures for the durable lower tiers."
            if coordinated_transactions
            else "Configure a TransactionalEvictionStore such as SQLiteStore."
        ),
        (
            (
                "L1 active state is checkpointed after Oracle mutations and restored at startup."
                if coordinated_transactions
                else "A crash can lose or split lower-tier eviction writes."
            ),
        ),
    )
    if not coordinated_transactions:
        blockers.append("No durable cross-tier transaction coordinator is configured.")

    thread_safety = CapabilityCheck(
        "thread_safety",
        CapabilityStatus.DEGRADED,
        (
            "Core mutations use reentrant locks; the durable lower tiers also coordinate across processes."
            if archive_cross_process and coordinated_transactions
            else "Core mutations use reentrant locks; lower tiers lack cross-process transaction coordination."
        ),
        (
            "Do not mutate returned Vine objects directly; use Oracle/Workspace methods."
            if coordinated_transactions
            else "Use Oracle/Workspace methods and configure cross-process coordination around persistent backends."
        ),
        (
            "Vine objects returned to callers remain mutable outside internal locks.",
            (
                "Cross-process coordination covers L2/L3 only, not mutable L1 Vine objects."
                if coordinated_transactions
                else "No cross-process locking or transactional persistence is provided."
            ),
        ),
    )
    warnings.append(
        "Internal operations are thread-serialized, but externally mutated Vine objects are not protected."
    )

    confidence = CapabilityCheck(
        "confidence_gating",
        CapabilityStatus.READY,
        "Confidence gating is implemented through Oracle.check_generation_gate().",
        "Catch GenerationGated and surface user override/escalation UI.",
    )

    # Development can be honest/degraded without being blocked from local use.
    if environment in {"staging", "production"} and blockers:
        overall = CapabilityStatus.BLOCKED
    elif blockers or warnings:
        overall = CapabilityStatus.DEGRADED
    else:
        overall = CapabilityStatus.READY

    return CapabilityReport(
        environment=environment,
        overall_status=overall,
        crypto_readiness=crypto,
        storage_backend=storage,
        vector_index_backend=vector_index,
        persistence=persistence,
        thread_safety=thread_safety,
        confidence_gating=confidence,
        production_blockers=tuple(blockers),
        warnings=tuple(warnings),
        known_limitations=tuple(
            limitation
            for limitation in (
                (
                    "Configured L2 search is linear and has no large-corpus latency guarantee."
                    if search_is_linear
                    else ""
                ),
                (
                    "Durable L2/L3 storage is not configured."
                    if not coordinated_transactions
                    else ""
                ),
            )
            if limitation
        ),
    )
