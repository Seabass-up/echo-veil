"""Echo Veil: a tiered, decay-driven memory architecture for conversational agents.

This package is a faithful, honest implementation of the implementable core of
the Echo Veil v1.0 specification. The Level-5 cryptographic shield is provided
as an interface plus an explicit stub, not a working implementation -- see
``echo_veil.crypto_shield`` and docs/ARCHITECTURE_NOTES.md.
"""

from __future__ import annotations

__version__ = "0.3.0"

from .capability import CapabilityCheck, CapabilityReport, CapabilityStatus
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
    EnclaveCryptoShield,
    NullCryptoShield,
    ProtectedVector,
)
from .drift import DriftDetector
from .oracle import GenerationGated, Oracle
from .proximity import ProximityConfig, proximity_score, time_decay
from .vectors import cosine_similarity, normalize
from .vine import Vine, VineState
from .workspace import Workspace, WorkspaceConfig

# EnclaveCryptoShield remains exported for compatibility, but construction
# raises NotImplementedError because the CKKS/enclave/ZK layer is not built.

__all__ = [
    "__version__",
    "Oracle",
    "GenerationGated",
    "CapabilityCheck",
    "CapabilityReport",
    "CapabilityStatus",
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
    "CryptoShield",
    "NullCryptoShield",
    "AesGcmCryptoShield",
    "EnclaveCryptoShield",
    "ProtectedVector",
    "cosine_similarity",
    "normalize",
]
