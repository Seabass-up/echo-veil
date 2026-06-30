"""Cryptographic Root Shield interfaces and implementations.

The spec's full Level-5 shield describes CKKS homomorphic encryption, hardware
enclave thresholding, and a zk-SNARK attestation gate. That research stack is
still **not** faked here.

What is provided:
  - CryptoShield: the interface the rest of the system codes against.
  - NullCryptoShield: development-only plaintext pass-through.
  - AesGcmCryptoShield: a practical symmetric encryption shield using
    AES-256-GCM for protected vector storage. It decrypts transiently inside
    ``similarity()`` to compute cosine similarity, so it is a real
    confidentiality improvement for protected anchor storage, but it is not
    homomorphic encryption and does not protect against a compromised Python
    process while similarity is being computed.
  - EnclaveCryptoShield: the CKKS + enclave + zk-SNARK placeholder. It remains
    intentionally unconstructable until a real threat model and implementation
    exist.

See docs/ARCHITECTURE_NOTES.md, section "Crypto shield: status and path".
"""

from __future__ import annotations

import base64
import json
import os
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol, TypeGuard, runtime_checkable

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .vectors import Vector, as_vector, cosine_similarity

AES_256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
DEFAULT_KEY_ENV = "ECHO_VEIL_CRYPTO_KEY"


def _decode_urlsafe_base64(value: str, field_name: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError(f"{field_name} is not valid base64") from exc


@dataclass(frozen=True)
class ProtectedVector:
    """AES-GCM protected vector payload.

    ``shape`` and ``dtype`` are authenticated as associated data. They are not
    secret, but authenticating them prevents metadata substitution attacks that
    would reinterpret decrypted bytes incorrectly.
    """

    algorithm: str
    nonce: bytes
    ciphertext: bytes
    shape: tuple[int, ...]
    dtype: str = "float64"

    def associated_data(self) -> bytes:
        payload = {
            "algorithm": self.algorithm,
            "shape": list(self.shape),
            "dtype": self.dtype,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")

    def as_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "nonce_b64": base64.urlsafe_b64encode(self.nonce).decode("ascii"),
            "ciphertext_b64": base64.urlsafe_b64encode(self.ciphertext).decode("ascii"),
            "shape": list(self.shape),
            "dtype": self.dtype,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_dict(cls, payload: dict[str, object]) -> "ProtectedVector":
        """Rebuild a protected vector from its JSON-compatible representation."""
        algorithm_value = payload.get("algorithm")
        nonce_value = payload.get("nonce_b64")
        ciphertext_value = payload.get("ciphertext_b64")
        shape_value = payload.get("shape")
        dtype_value = payload.get("dtype", "float64")

        if not isinstance(algorithm_value, str) or not algorithm_value:
            raise ValueError("Invalid protected vector payload")
        if not isinstance(nonce_value, str) or not isinstance(ciphertext_value, str):
            raise ValueError("Invalid protected vector payload")
        if not isinstance(dtype_value, str) or not dtype_value:
            raise ValueError("Invalid protected vector payload")
        if not isinstance(shape_value, Sequence) or isinstance(shape_value, (str, bytes, bytearray)):
            raise ValueError("Invalid protected vector payload")

        shape_parts: list[int] = []
        for part in shape_value:
            if isinstance(part, bool) or not isinstance(part, int) or part <= 0:
                raise ValueError("Invalid protected vector payload")
            shape_parts.append(part)
        if len(shape_parts) != 1:
            raise ValueError("Invalid protected vector payload")

        nonce = _decode_urlsafe_base64(nonce_value, "nonce_b64")
        ciphertext = _decode_urlsafe_base64(ciphertext_value, "ciphertext_b64")
        if len(nonce) != AES_GCM_NONCE_BYTES or not ciphertext:
            raise ValueError("Invalid protected vector payload")
        return cls(
            algorithm=algorithm_value,
            nonce=nonce,
            ciphertext=ciphertext,
            shape=tuple(shape_parts),
            dtype=dtype_value,
        )

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> "ProtectedVector":
        """Rebuild a protected vector from ``to_json_bytes()`` output."""
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Invalid protected vector JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("Invalid protected vector JSON")
        return cls.from_dict(decoded)


@runtime_checkable
class CryptoShield(Protocol):
    """Contract for the memory-space confidentiality layer."""

    def protect(self, anchor: Vector) -> object:
        """Wrap a plaintext anchor into the shield's protected representation."""
        ...

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        """Compute similarity between a plaintext intent and a protected anchor."""
        ...


@runtime_checkable
class SerializableProtectedPayload(Protocol):
    """Protected payloads that can be archived without plaintext fallback."""

    def to_json_bytes(self) -> bytes:
        """Return authenticated/serialized protected payload bytes."""
        ...


def is_crypto_shield(candidate: object) -> TypeGuard[CryptoShield]:
    """Return True when an object structurally satisfies the shield contract."""
    return (
        callable(getattr(candidate, "protect", None))
        and callable(getattr(candidate, "similarity", None))
    )


def is_serializable_protected_payload(candidate: object) -> TypeGuard[SerializableProtectedPayload]:
    """Return True when a protected payload can be archived as bytes."""
    return callable(getattr(candidate, "to_json_bytes", None))


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


class AesGcmCryptoShield:
    """Practical AES-256-GCM vector shield.

    This shield encrypts anchor vectors at rest/in protected storage and
    authenticates vector metadata. ``similarity()`` decrypts the vector only for
    the duration of the calculation and zeroes the temporary byte buffer in a
    ``finally`` block. Python cannot guarantee perfect in-process secret
    erasure, so this does **not** claim enclave-grade protection.

    Key handling:
    - pass a 32-byte key from a secret manager, or
    - load a URL-safe base64 32-byte key from ``ECHO_VEIL_CRYPTO_KEY``.
    """

    algorithm = "AES-256-GCM"

    def __init__(self, key: bytes) -> None:
        if len(key) != AES_256_KEY_BYTES:
            raise ValueError(f"AesGcmCryptoShield key must be {AES_256_KEY_BYTES} bytes")
        self._key = bytes(key)
        self._aesgcm = AESGCM(self._key)

    @staticmethod
    def generate_key() -> bytes:
        """Return a new random 256-bit key."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def key_to_base64(key: bytes) -> str:
        """Encode a 32-byte key for environment-variable storage."""
        if len(key) != AES_256_KEY_BYTES:
            raise ValueError(f"AesGcmCryptoShield key must be {AES_256_KEY_BYTES} bytes")
        return base64.urlsafe_b64encode(key).decode("ascii")

    @staticmethod
    def key_from_base64(value: str) -> bytes:
        """Decode and validate a URL-safe base64 key."""
        key = _decode_urlsafe_base64(value, "AesGcmCryptoShield key")
        if len(key) != AES_256_KEY_BYTES:
            raise ValueError(f"AesGcmCryptoShield key must decode to {AES_256_KEY_BYTES} bytes")
        return key

    @classmethod
    def from_env(cls, env_var: str = DEFAULT_KEY_ENV) -> "AesGcmCryptoShield":
        """Create a shield from a base64 key stored in an environment variable."""
        raw = os.environ.get(env_var, "").strip()
        if not raw:
            raise ValueError(f"{env_var} is not set")
        return cls(cls.key_from_base64(raw))

    def protect(self, anchor: Vector) -> ProtectedVector:
        arr = as_vector(anchor).astype(np.float64, copy=False)
        if arr.size == 0:
            raise ValueError("AesGcmCryptoShield cannot protect an empty anchor vector")
        protected = ProtectedVector(
            algorithm=self.algorithm,
            nonce=os.urandom(AES_GCM_NONCE_BYTES),
            ciphertext=b"",
            shape=tuple(int(part) for part in arr.shape),
            dtype="float64",
        )
        ciphertext = self._aesgcm.encrypt(
            protected.nonce,
            arr.tobytes(order="C"),
            protected.associated_data(),
        )
        return ProtectedVector(
            algorithm=protected.algorithm,
            nonce=protected.nonce,
            ciphertext=ciphertext,
            shape=protected.shape,
            dtype=protected.dtype,
        )

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        if not isinstance(protected_anchor, ProtectedVector):
            raise TypeError("AesGcmCryptoShield expects a ProtectedVector")
        if protected_anchor.algorithm != self.algorithm or protected_anchor.dtype != "float64":
            raise ValueError("Unsupported protected vector metadata")

        anchor = self.reveal(protected_anchor)
        return cosine_similarity(intent, anchor)

    def reveal(self, protected_anchor: ProtectedVector) -> Vector:
        """Decrypt a protected vector for internal operations that need plaintext.

        This is intentionally narrow: callers should prefer ``similarity()``
        where possible. Drift centroids and archive resurrection need the
        actual vector shape, so the AES implementation exposes a controlled
        round-trip path while still authenticating metadata.
        """
        if protected_anchor.algorithm != self.algorithm or protected_anchor.dtype != "float64":
            raise ValueError("Unsupported protected vector metadata")

        plaintext = bytearray()
        try:
            plaintext = bytearray(
                self._aesgcm.decrypt(
                    protected_anchor.nonce,
                    protected_anchor.ciphertext,
                    protected_anchor.associated_data(),
                )
            )
            expected_bytes = int(np.prod(protected_anchor.shape)) * np.dtype(np.float64).itemsize
            if len(plaintext) != expected_bytes:
                raise ValueError("Protected vector plaintext size does not match metadata")
            return np.frombuffer(plaintext, dtype=np.float64).reshape(protected_anchor.shape).copy()
        except InvalidTag as exc:
            raise ValueError("Could not decrypt protected vector; authentication failed") from exc
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0


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
            "for the requirements and a phased path. Use AesGcmCryptoShield for "
            "practical encrypted vector storage or NullCryptoShield for development only."
        )
