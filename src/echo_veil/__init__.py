"""Echo Veil: a shielded four-layer living-memory substrate for AI agents.

This package implements semantic memory policy, durable tiered storage, and a
fail-closed adapter for attested CKKS enclave providers.
"""

from __future__ import annotations

__version__ = "0.7.0"

from .capability import CapabilityCheck, CapabilityReport, CapabilityStatus
from .agent_memory import AgentMemory, HashingTextEmbedder, OllamaTextEmbedder
from .cloudflare_provider import CloudflareEnclaveProvider, CloudflareGatewayError
from .azure_attestation import AzureMaaJwtVerifier
from .confidence import ConfidenceBand, classify
from .conflict import (
    ConflictVine,
    FossilizedEcho,
    fossilize,
    in_peer_review_zone,
    open_conflict,
    resurrect,
)
from .crypto_shield import (
    AesGcmCryptoShield,
    CryptoShield,
    EnclaveProtectedVector,
    EnclaveCryptoShield,
    Ed25519AttestationVerifier,
    LocalOpenFheCryptoShield,
    NullCryptoShield,
    ProductionCryptoShield,
    ProtectedVector,
    VerifiedEnclave,
    load_protected_vector,
)
from .drift import DriftDetector
from .deployment import build_production_enclave_shield_from_env
from .memory_layers import LogicKind, MemoryLayer, MemoryLayerContract
from .local_readiness import (
    LocalReadinessEvidence,
    LocalReadinessState,
    build_capabilities_v1,
)
from .oracle import GenerationGated, Oracle
from .persistence import SQLiteColdArchive, SQLiteMetadataIndex, SQLiteStore
from .preflight_receipt import (
    PreflightReceiptAuthority,
    PreflightReceiptVerifier,
)
from .proximity import ProximityConfig, proximity_score, time_decay
from .vectors import cosine_similarity, normalize
from .vine import Vine, VineState
from .workspace import Workspace, WorkspaceConfig
from .zkp import RistrettoSchnorrProofProvider

__all__ = [
    "__version__",
    "AgentMemory",
    "HashingTextEmbedder",
    "OllamaTextEmbedder",
    "MemoryLayer",
    "MemoryLayerContract",
    "LogicKind",
    "LocalReadinessEvidence",
    "LocalReadinessState",
    "build_capabilities_v1",
    "Oracle",
    "GenerationGated",
    "SQLiteStore",
    "SQLiteMetadataIndex",
    "SQLiteColdArchive",
    "PreflightReceiptAuthority",
    "PreflightReceiptVerifier",
    "CapabilityCheck",
    "CapabilityReport",
    "CapabilityStatus",
    "CloudflareEnclaveProvider",
    "CloudflareGatewayError",
    "AzureMaaJwtVerifier",
    "Workspace",
    "WorkspaceConfig",
    "Vine",
    "VineState",
    "ProximityConfig",
    "proximity_score",
    "time_decay",
    "ConfidenceBand",
    "classify",
    "ConflictVine",
    "FossilizedEcho",
    "open_conflict",
    "fossilize",
    "resurrect",
    "in_peer_review_zone",
    "DriftDetector",
    "build_production_enclave_shield_from_env",
    "CryptoShield",
    "ProductionCryptoShield",
    "NullCryptoShield",
    "AesGcmCryptoShield",
    "LocalOpenFheCryptoShield",
    "EnclaveCryptoShield",
    "EnclaveProtectedVector",
    "Ed25519AttestationVerifier",
    "VerifiedEnclave",
    "ProtectedVector",
    "load_protected_vector",
    "RistrettoSchnorrProofProvider",
    "cosine_similarity",
    "normalize",
]
