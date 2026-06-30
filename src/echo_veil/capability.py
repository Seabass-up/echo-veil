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

from .archive import ColdArchive, MetadataIndex
from .crypto_shield import AesGcmCryptoShield, NullCryptoShield, is_crypto_shield


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
            ("CKKS/enclave/zk-SNARK shield is not implemented.",),
        )
        blockers.append("NullCryptoShield is not production-ready.")
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
        blockers.append("Custom CryptoShield requires external validation before production use.")

    archive = getattr(oracle, "archive", None)
    storage_is_reference = isinstance(archive, ColdArchive)
    storage = CapabilityCheck(
        "storage_backend",
        CapabilityStatus.DEGRADED if storage_is_reference else CapabilityStatus.READY,
        "ColdArchive is an in-memory reference backend." if storage_is_reference else f"Storage backend: {type(archive).__name__}.",
        "Swap in durable object storage for production." if storage_is_reference else "Validate durability and access controls.",
        ("In-memory archive is lost on process restart.",) if storage_is_reference else (),
    )
    if storage_is_reference:
        blockers.append("ColdArchive is in-memory/reference storage.")

    index = getattr(oracle, "index", None)
    index_is_reference = isinstance(index, MetadataIndex)
    vector_index = CapabilityCheck(
        "vector_index_backend",
        CapabilityStatus.DEGRADED if index_is_reference else CapabilityStatus.READY,
        "MetadataIndex is a linear-scan in-memory reference index." if index_is_reference else f"Vector index backend: {type(index).__name__}.",
        "Swap in an ANN/vector DB backend before relying on low-latency global lookup." if index_is_reference else "Validate latency and recall behavior.",
        ("No <5ms global lookup guarantee with reference index.",) if index_is_reference else (),
    )
    if index_is_reference:
        blockers.append("MetadataIndex is a reference linear-scan index.")

    persistence = CapabilityCheck(
        "persistence",
        CapabilityStatus.BLOCKED,
        "No durable persistence layer is configured for L1/L2/L3 state.",
        "Add persistence behind storage/index interfaces before production stateful use.",
        ("Process restart loses in-memory state.",),
    )
    blockers.append("No durable persistence layer is configured.")

    thread_safety = CapabilityCheck(
        "thread_safety",
        CapabilityStatus.DEGRADED,
        "Workspace uses plain in-memory dictionaries without locking.",
        "Single-thread access or add locking before multi-threaded hosts.",
        ("Concurrent mutation can corrupt workspace state.",),
    )
    warnings.append("Thread safety is not production-grade for concurrent hosts.")

    confidence = CapabilityCheck(
        "confidence_gating",
        CapabilityStatus.READY,
        "Confidence gating is implemented through Oracle.check_generation_gate().",
        "Catch GenerationGated and surface user override/escalation UI.",
    )

    # Development can be honest/degraded without being blocked from local use.
    if environment == "production" and blockers:
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
        known_limitations=(
            "Level-5 cryptographic root shield is interface/stub only.",
            "L2/L3 backends are in-memory reference implementations.",
            "No persistence or cross-process concurrency control is provided.",
        ),
    )
