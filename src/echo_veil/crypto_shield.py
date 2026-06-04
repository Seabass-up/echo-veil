"""Cryptographic Root Shield (Section 5) -- INTERFACE + HONEST STUB.

The spec describes a Level-5 shield combining three independently hard
technologies:

  1. CKKS homomorphic encryption of all 768-dim anchor vectors, with cosine
     similarity evaluated as dot products over ciphertext;
  2. a hardware enclave (Intel SGX / AMD SEV-SNP) inside which decryption and
     thresholding occur;
  3. a zk-SNARK remote-attestation gate proving key possession + host integrity
     before any operation.

This combination is NOT implemented here, and is deliberately not faked. Each
piece is a serious research/engineering effort on its own; composing them into
a "production-ready" layer is well beyond what the spec actually specifies
(it gives topology and naming, not protocols, parameters, or a threat model).
Shipping a stub that *looked* like working crypto would be worse than shipping
nothing, because it would invite false trust.

What IS provided:
  - CryptoShield: the interface the rest of the system codes against.
  - NullCryptoShield: a pass-through, NO-OP implementation for development and
    testing ONLY. It provides zero confidentiality and says so loudly.
  - EnclaveCryptoShield: the real-layer placeholder. Construction raises
    NotImplementedError with pointers to what a real build requires.

See docs/ARCHITECTURE_NOTES.md, section "Crypto shield: status and path".
"""

from __future__ import annotations

import warnings
from typing import Protocol

from .vectors import Vector, cosine_similarity


class CryptoShield(Protocol):
    """Contract for the memory-space confidentiality layer."""

    def protect(self, anchor: Vector) -> object:
        """Wrap a plaintext anchor into the shield's protected representation."""
        ...

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        """Compute similarity between a plaintext intent and a protected anchor."""
        ...


class NullCryptoShield:
    """Development-only pass-through. PROVIDES NO CONFIDENTIALITY.

    Anchors are stored in plaintext. Use only in local dev/tests. A warning is
    emitted on construction so it cannot slip into production unnoticed.
    """

    def __init__(self, silence_warning: bool = False) -> None:
        if not silence_warning:
            warnings.warn(
                "NullCryptoShield provides NO confidentiality. "
                "Do not use outside development/testing.",
                stacklevel=2,
            )

    def protect(self, anchor: Vector) -> Vector:
        return anchor  # plaintext

    def similarity(self, intent: Vector, protected_anchor: Vector) -> float:
        return cosine_similarity(intent, protected_anchor)


class EnclaveCryptoShield:
    """Placeholder for the real CKKS + enclave + zk-SNARK shield.

    Intentionally unconstructable. A genuine implementation needs, at minimum:
      - a vetted CKKS library (e.g. OpenFHE / Microsoft SEAL) with chosen
        parameters and a documented security level;
      - an enclave runtime + attestation flow (SGX DCAP or SEV-SNP) and the
        operational story for sealing/rotating keys;
      - a zk-SNARK circuit + trusted-setup or transparent proof system for the
        attestation gate, plus a verifier;
      - a written threat model defining exactly what each layer defends against.
    """

    def __init__(self, *args, **kwargs) -> None:
        raise NotImplementedError(
            "EnclaveCryptoShield is a placeholder. The CKKS + hardware-enclave + "
            "zk-SNARK shield is not implemented; see docs/ARCHITECTURE_NOTES.md "
            "for the requirements and a phased path. Use NullCryptoShield for "
            "development only."
        )
