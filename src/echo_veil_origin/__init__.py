"""Confidential-VM origin service for the Echo Veil enclave protocol."""

from .core import (
    AttestationSigner,
    EnclaveService,
    OriginConfig,
    ProtocolError,
    VerifiedProof,
)
from .openfhe_engine import OpenFheCkksEngine
from .native_attestation import AzureMaaEvidenceProvider
from .proof_verifier import RistrettoProofVerifier

__all__ = [
    "AttestationSigner",
    "AzureMaaEvidenceProvider",
    "EnclaveService",
    "OpenFheCkksEngine",
    "OriginConfig",
    "ProtocolError",
    "RistrettoProofVerifier",
    "VerifiedProof",
]
