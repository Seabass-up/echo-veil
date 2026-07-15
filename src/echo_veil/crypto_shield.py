"""Cryptographic Root Shield interfaces and implementations.

The spec's full Level-5 shield describes CKKS homomorphic encryption, hardware
enclave thresholding, and a zk-SNARK attestation gate. Echo Veil implements a
fail-closed integration boundary for a deployment-provided implementation.

What is provided:
  - CryptoShield: the interface the rest of the system codes against.
  - NullCryptoShield: development-only plaintext pass-through.
  - AesGcmCryptoShield: a practical symmetric encryption shield using
    AES-256-GCM for protected vector storage. It decrypts transiently inside
    ``similarity()`` to compute cosine similarity, so it is a real
    confidentiality improvement for protected anchor storage, but it is not
    homomorphic encryption and does not protect against a compromised Python
    process while similarity is being computed.
  - EnclaveCryptoShield: verifies fresh deployment attestation claims and opens
    a provider session only after the configured ZKP proof is accepted.

See docs/ARCHITECTURE_NOTES.md, section "Crypto shield: trust boundary".
"""

from __future__ import annotations

import base64
import hmac
import json
import math
import os
import time
import warnings
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol, TypeGuard, runtime_checkable

import numpy as np
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .vectors import Vector, as_vector, cosine_similarity

AES_256_KEY_BYTES = 32
AES_GCM_NONCE_BYTES = 12
AES_GCM_TAG_BYTES = 16
MAX_VECTOR_ELEMENTS = 1_000_000
MAX_PROTECTED_VECTOR_JSON_BYTES = 12_000_000
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

    def __post_init__(self) -> None:
        if not isinstance(self.algorithm, str) or not self.algorithm:
            raise ValueError("Invalid protected vector payload")
        if not isinstance(self.dtype, str) or not self.dtype:
            raise ValueError("Invalid protected vector payload")
        if not isinstance(self.nonce, bytes) or len(self.nonce) != AES_GCM_NONCE_BYTES:
            raise ValueError("Invalid protected vector payload")
        if (
            not isinstance(self.ciphertext, bytes)
            or not AES_GCM_TAG_BYTES
            <= len(self.ciphertext)
            <= MAX_VECTOR_ELEMENTS * np.dtype(np.float64).itemsize + AES_GCM_TAG_BYTES
        ):
            raise ValueError("Invalid protected vector payload")
        if (
            not isinstance(self.shape, tuple)
            or len(self.shape) != 1
            or isinstance(self.shape[0], bool)
            or not isinstance(self.shape[0], int)
            or not 0 < self.shape[0] <= MAX_VECTOR_ELEMENTS
        ):
            raise ValueError("Invalid protected vector payload")

    def associated_data(self) -> bytes:
        payload = {
            "algorithm": self.algorithm,
            "shape": list(self.shape),
            "dtype": self.dtype,
        }
        return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def as_dict(self) -> dict[str, object]:
        return {
            "algorithm": self.algorithm,
            "nonce_b64": base64.urlsafe_b64encode(self.nonce).decode("ascii"),
            "ciphertext_b64": base64.urlsafe_b64encode(self.ciphertext).decode("ascii"),
            "shape": list(self.shape),
            "dtype": self.dtype,
        }

    def to_json_bytes(self) -> bytes:
        return json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

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
        if not isinstance(shape_value, Sequence) or isinstance(
            shape_value, (str, bytes, bytearray)
        ):
            raise ValueError("Invalid protected vector payload")

        shape_parts: list[int] = []
        for part in shape_value:
            if (
                isinstance(part, bool)
                or not isinstance(part, int)
                or not 0 < part <= MAX_VECTOR_ELEMENTS
            ):
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
        if not isinstance(payload, bytes):
            raise TypeError("protected vector JSON must be bytes")
        if len(payload) > MAX_PROTECTED_VECTOR_JSON_BYTES:
            raise ValueError("Invalid protected vector JSON: payload is too large")
        try:
            decoded = json.loads(payload.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Invalid protected vector JSON") from exc
        if not isinstance(decoded, dict):
            raise ValueError("Invalid protected vector JSON")
        return cls.from_dict(decoded)


@dataclass(frozen=True)
class VerifiedEnclave:
    """Security claims returned by a deployment's trusted attestation verifier."""

    provider_id: str
    measurement: str
    key_id: str
    expires_at: float
    ckks_security_bits: int
    hardware_isolation: bool
    zkp_access_gate: bool
    homomorphic_similarity: bool
    transport_public_key: bytes

    def __post_init__(self) -> None:
        if not self.provider_id or not self.measurement or not self.key_id:
            raise ValueError("verified enclave identifiers must be non-empty")
        if not math.isfinite(self.expires_at) or self.expires_at <= 0.0:
            raise ValueError("verified enclave expiry must be finite")
        if (
            isinstance(self.ckks_security_bits, bool)
            or not isinstance(self.ckks_security_bits, int)
            or self.ckks_security_bits <= 0
        ):
            raise ValueError("verified CKKS security bits must be positive")
        if not all(
            isinstance(value, bool)
            for value in (
                self.hardware_isolation,
                self.zkp_access_gate,
                self.homomorphic_similarity,
            )
        ):
            raise TypeError("verified enclave capability claims must be bools")
        if (
            not isinstance(self.transport_public_key, bytes)
            or len(self.transport_public_key) != 32
        ):
            raise ValueError("verified enclave transport key must be 32 bytes")


@dataclass(frozen=True)
class EnclaveProtectedVector:
    """Opaque CKKS ciphertext owned by an attested enclave provider."""

    provider_id: str
    key_id: str
    ciphertext: bytes
    shape: tuple[int, ...]
    algorithm: str = "CKKS"

    def __post_init__(self) -> None:
        if not self.provider_id or not self.key_id:
            raise ValueError("enclave provider_id and key_id must be non-empty")
        if not isinstance(self.ciphertext, bytes) or not self.ciphertext:
            raise ValueError("enclave ciphertext must be non-empty bytes")
        if len(self.shape) != 1 or self.shape[0] <= 0:
            raise ValueError("enclave protected vector must have a positive 1-D shape")

    def to_json_bytes(self) -> bytes:
        return json.dumps(
            {
                "algorithm": self.algorithm,
                "provider_id": self.provider_id,
                "key_id": self.key_id,
                "ciphertext_b64": base64.urlsafe_b64encode(self.ciphertext).decode(
                    "ascii"
                ),
                "shape": list(self.shape),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, payload: bytes) -> EnclaveProtectedVector:
        try:
            value = json.loads(payload.decode("utf-8"))
            if not isinstance(value, dict) or value.get("algorithm") != "CKKS":
                raise ValueError
            shape = value["shape"]
            if not isinstance(shape, list) or len(shape) != 1:
                raise ValueError
            return cls(
                provider_id=str(value["provider_id"]),
                key_id=str(value["key_id"]),
                ciphertext=_decode_urlsafe_base64(
                    str(value["ciphertext_b64"]), "ciphertext_b64"
                ),
                shape=(int(shape[0]),),
            )
        except Exception as exc:
            raise ValueError("Invalid enclave protected vector JSON") from exc


class EnclaveProvider(Protocol):
    """Transport contract implemented by an SGX/SEV-SNP CKKS service client."""

    def attest(self, nonce: bytes) -> bytes: ...

    def bind_attestation(self, enclave: VerifiedEnclave) -> None: ...

    def access_challenge(self) -> bytes: ...

    def open_session(self, proof: bytes) -> str: ...

    def encrypt_vector(self, session: str, anchor: Vector) -> bytes: ...

    def cosine_similarity(
        self, session: str, intent: Vector, ciphertext: bytes
    ) -> float: ...


class AttestationVerifier(Protocol):
    """Verify vendor attestation evidence against a deployment trust policy."""

    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedEnclave: ...


class ZeroKnowledgeProofProvider(Protocol):
    """Create the deployment-specific proof accepted by the enclave ZKP gate."""

    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes: ...


class Ed25519AttestationVerifier:
    """Verify normalized enclave claims signed by a deployment trust root.

    The signing authority is expected to validate native SGX DCAP or SEV-SNP
    evidence before issuing this bounded JSON envelope. Measurement allowlisting
    remains local so a valid signature for an unapproved image still fails.
    """

    def __init__(
        self,
        public_key: Ed25519PublicKey,
        allowed_measurements: set[str] | frozenset[str],
        *,
        maximum_lifetime_seconds: float = 300.0,
    ) -> None:
        if not isinstance(public_key, Ed25519PublicKey):
            raise TypeError("public_key must be an Ed25519PublicKey")
        measurements = frozenset(allowed_measurements)
        if not measurements or not all(
            isinstance(value, str) and value for value in measurements
        ):
            raise ValueError("allowed_measurements must contain non-empty strings")
        if maximum_lifetime_seconds <= 0:
            raise ValueError("maximum_lifetime_seconds must be positive")
        self._public_key = public_key
        self._measurements = measurements
        self._maximum_lifetime = float(maximum_lifetime_seconds)

    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedEnclave:
        try:
            envelope = json.loads(evidence.decode("utf-8"))
            if not isinstance(envelope, dict):
                raise ValueError
            payload = _decode_urlsafe_base64(
                str(envelope["payload_b64"]), "payload_b64"
            )
            signature = _decode_urlsafe_base64(
                str(envelope["signature_b64"]), "signature_b64"
            )
            self._public_key.verify(signature, payload)
            claims = json.loads(payload.decode("utf-8"))
            if not isinstance(claims, dict):
                raise ValueError
            bound_nonce = _decode_urlsafe_base64(str(claims["nonce_b64"]), "nonce_b64")
        except Exception as exc:
            raise ValueError(
                "attestation evidence signature or format is invalid"
            ) from exc
        if not hmac.compare_digest(bound_nonce, nonce):
            raise ValueError("attestation evidence is not bound to this nonce")
        measurement = str(claims.get("measurement", ""))
        if measurement not in self._measurements:
            raise ValueError("attestation measurement is not approved")
        issued_at = float(claims.get("issued_at", 0.0))
        expires_at = float(claims.get("expires_at", 0.0))
        current = time.time()
        if issued_at > current + 30.0 or expires_at <= current:
            raise ValueError("attestation evidence is not currently valid")
        if expires_at - issued_at > self._maximum_lifetime:
            raise ValueError("attestation evidence lifetime exceeds policy")
        return VerifiedEnclave(
            provider_id=str(claims.get("provider_id", "")),
            measurement=measurement,
            key_id=str(claims.get("key_id", "")),
            expires_at=expires_at,
            ckks_security_bits=int(claims.get("ckks_security_bits", 0)),
            hardware_isolation=claims.get("hardware_isolation") is True,
            zkp_access_gate=claims.get("zkp_access_gate") is True,
            homomorphic_similarity=claims.get("homomorphic_similarity") is True,
            transport_public_key=_decode_urlsafe_base64(
                str(claims.get("transport_public_key_b64", "")),
                "transport_public_key_b64",
            ),
        )


def load_protected_vector(payload: bytes) -> ProtectedVector | EnclaveProtectedVector:
    """Deserialize a built-in protected payload without exposing plaintext."""
    try:
        value = json.loads(payload.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Invalid protected vector JSON") from exc
    if not isinstance(value, dict):
        raise ValueError("Invalid protected vector JSON")
    if value.get("algorithm") == "CKKS":
        return EnclaveProtectedVector.from_json_bytes(payload)
    return ProtectedVector.from_json_bytes(payload)


@runtime_checkable
class CryptoShield(Protocol):
    """Contract for the memory-space confidentiality layer."""

    def protect(self, anchor: Vector) -> object:
        """Wrap a plaintext anchor into the shield's protected representation."""
        ...

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        """Compute similarity between a plaintext intent and a protected anchor."""
        ...


class LocalCkksEngine(Protocol):
    """Minimal OpenFHE engine contract used by the local-private shield."""

    key_id: str

    def encrypt_normalized(self, vector: Sequence[float]) -> bytes:
        raise NotImplementedError

    def cosine_similarity(
        self, normalized_intent: Sequence[float], ciphertext: bytes
    ) -> float:
        raise NotImplementedError

    def ciphertext_dimension(self, ciphertext: bytes) -> int:
        raise NotImplementedError


class ProductionCryptoShield(CryptoShield, Protocol):
    """A shield that explicitly opts into use in staging-like modes.

    This marker cannot prove cryptographic quality and is never sufficient for
    production, which requires ``EnclaveCryptoShield`` specifically. It prevents
    an arbitrary two-method object from silently bypassing the staging guard.
    """

    production_ready: bool


@runtime_checkable
class SerializableProtectedPayload(Protocol):
    """Protected payloads that can be archived without plaintext fallback."""

    def to_json_bytes(self) -> bytes:
        """Return authenticated/serialized protected payload bytes."""
        ...


def is_crypto_shield(candidate: object) -> TypeGuard[CryptoShield]:
    """Return True when an object structurally satisfies the shield contract."""
    return callable(getattr(candidate, "protect", None)) and callable(
        getattr(candidate, "similarity", None)
    )


def is_production_crypto_shield(
    candidate: object,
) -> TypeGuard[ProductionCryptoShield]:
    """Return True only for valid shields with an explicit readiness marker."""
    return (
        is_crypto_shield(candidate)
        and getattr(candidate, "production_ready", False) is True
    )


def is_serializable_protected_payload(
    candidate: object,
) -> TypeGuard[SerializableProtectedPayload]:
    """Return True when a protected payload can be archived as bytes."""
    return callable(getattr(candidate, "to_json_bytes", None))


class NullCryptoShield:
    """Development-only pass-through. PROVIDES NO CONFIDENTIALITY.

    Anchors are stored in plaintext. Use only in local dev/tests. A warning is
    emitted on construction so it cannot slip into production unnoticed.
    """

    production_ready = False

    def __init__(self, silence_warning: bool = False) -> None:
        if not silence_warning:
            warnings.warn(
                "NullCryptoShield provides NO confidentiality. "
                "Do not use outside development/testing.",
                stacklevel=2,
            )

    def protect(self, anchor: Vector) -> Vector:
        return as_vector(
            anchor,
            allow_empty=False,
            copy=True,
            name="anchor vector",
        )  # plaintext

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
    production_ready = False

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("AesGcmCryptoShield key must be bytes-like")
        key_bytes = bytes(key)
        if len(key_bytes) != AES_256_KEY_BYTES:
            raise ValueError(
                f"AesGcmCryptoShield key must be {AES_256_KEY_BYTES} bytes"
            )
        self._key = key_bytes
        self._aesgcm = AESGCM(self._key)

    @staticmethod
    def generate_key() -> bytes:
        """Return a new random 256-bit key."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def key_to_base64(key: bytes) -> str:
        """Encode a 32-byte key for environment-variable storage."""
        if not isinstance(key, (bytes, bytearray, memoryview)):
            raise TypeError("AesGcmCryptoShield key must be bytes-like")
        key_bytes = bytes(key)
        if len(key_bytes) != AES_256_KEY_BYTES:
            raise ValueError(
                f"AesGcmCryptoShield key must be {AES_256_KEY_BYTES} bytes"
            )
        return base64.urlsafe_b64encode(key_bytes).decode("ascii")

    @staticmethod
    def key_from_base64(value: str) -> bytes:
        """Decode and validate a URL-safe base64 key."""
        key = _decode_urlsafe_base64(value, "AesGcmCryptoShield key")
        if len(key) != AES_256_KEY_BYTES:
            raise ValueError(
                f"AesGcmCryptoShield key must decode to {AES_256_KEY_BYTES} bytes"
            )
        return key

    @classmethod
    def from_env(cls, env_var: str = DEFAULT_KEY_ENV) -> "AesGcmCryptoShield":
        """Create a shield from a base64 key stored in an environment variable."""
        raw = os.environ.get(env_var, "").strip()
        if not raw:
            raise ValueError(f"{env_var} is not set")
        return cls(cls.key_from_base64(raw))

    def protect(self, anchor: Vector) -> ProtectedVector:
        arr = as_vector(
            anchor,
            allow_empty=True,
            name="anchor vector",
        ).astype(np.float64, copy=False)
        if arr.size == 0:
            raise ValueError("AesGcmCryptoShield cannot protect an empty anchor vector")
        if arr.size > MAX_VECTOR_ELEMENTS:
            raise ValueError(
                f"anchor vector exceeds the {MAX_VECTOR_ELEMENTS}-element safety limit"
            )
        nonce = os.urandom(AES_GCM_NONCE_BYTES)
        shape = tuple(int(part) for part in arr.shape)
        associated_data = json.dumps(
            {
                "algorithm": self.algorithm,
                "shape": list(shape),
                "dtype": "float64",
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        ciphertext = self._aesgcm.encrypt(
            nonce,
            arr.tobytes(order="C"),
            associated_data,
        )
        return ProtectedVector(
            algorithm=self.algorithm,
            nonce=nonce,
            ciphertext=ciphertext,
            shape=shape,
            dtype="float64",
        )

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        anchor = self.reveal(protected_anchor)
        return cosine_similarity(intent, anchor)

    def reveal(self, protected_anchor: object) -> Vector:
        """Decrypt a protected vector for internal operations that need plaintext.

        This is intentionally narrow: callers should prefer ``similarity()``
        where possible. Drift centroids and archive resurrection need the
        actual vector shape, so the AES implementation exposes a controlled
        round-trip path while still authenticating metadata.
        """
        protected = self._validate_protected_vector(protected_anchor)

        plaintext = bytearray()
        try:
            plaintext = bytearray(
                self._aesgcm.decrypt(
                    protected.nonce,
                    protected.ciphertext,
                    protected.associated_data(),
                )
            )
            expected_bytes = protected.shape[0] * np.dtype(np.float64).itemsize
            if len(plaintext) != expected_bytes:
                raise ValueError(
                    "Protected vector plaintext size does not match metadata"
                )
            return (
                np.frombuffer(plaintext, dtype=np.float64)
                .reshape(protected.shape)
                .copy()
            )
        except InvalidTag as exc:
            raise ValueError(
                "Could not decrypt protected vector; authentication failed"
            ) from exc
        finally:
            for index in range(len(plaintext)):
                plaintext[index] = 0

    def _validate_protected_vector(
        self,
        protected_anchor: object,
    ) -> ProtectedVector:
        if not isinstance(protected_anchor, ProtectedVector):
            raise TypeError("AesGcmCryptoShield expects a ProtectedVector")
        if (
            protected_anchor.algorithm != self.algorithm
            or protected_anchor.dtype != "float64"
        ):
            raise ValueError("Unsupported protected vector metadata")
        expected_ciphertext_bytes = (
            protected_anchor.shape[0] * np.dtype(np.float64).itemsize
            + AES_GCM_TAG_BYTES
        )
        if len(protected_anchor.ciphertext) != expected_ciphertext_bytes:
            raise ValueError("Protected vector ciphertext size does not match metadata")
        return protected_anchor


class LocalOpenFheCryptoShield:
    """Run OpenFHE CKKS directly on a user's local machine.

    This profile keeps vectors, ciphertexts, and key material on the device and
    performs similarity homomorphically. It deliberately does not claim remote
    attestation or hardware-enclave isolation: a process with access to the
    local account can potentially access the OpenFHE secret-key state.
    """

    algorithm = "CKKS"
    provider_id = "local-openfhe"
    production_ready = False
    local_private_ready = True

    def __init__(self, engine: LocalCkksEngine) -> None:
        key_id = getattr(engine, "key_id", None)
        if not isinstance(key_id, str) or not key_id:
            raise ValueError("local OpenFHE engine must expose a non-empty key_id")
        for method in (
            "encrypt_normalized",
            "cosine_similarity",
            "ciphertext_dimension",
        ):
            if not callable(getattr(engine, method, None)):
                raise TypeError(f"local OpenFHE engine must implement {method}()")
        self._engine = engine
        self.key_id = key_id

    @classmethod
    def from_directory(
        cls,
        state_directory: str | Path,
        *,
        key_id: str = "echo-veil-local-v1",
        batch_size: int = 16_384,
        create_keys: bool = False,
    ) -> LocalOpenFheCryptoShield:
        """Load or initialize owner-local OpenFHE key state."""
        from echo_veil_origin.openfhe_engine import OpenFheCkksEngine

        return cls(
            OpenFheCkksEngine(
                key_id,
                state_directory,
                batch_size=batch_size,
                create_keys=create_keys,
            )
        )

    @staticmethod
    def _normalize(vector: Vector, label: str) -> Vector:
        value = as_vector(vector, allow_empty=False, name=label)
        norm = float(np.linalg.norm(value))
        if not math.isfinite(norm) or norm <= 1e-15:
            raise ValueError(f"{label} must have a non-zero finite norm")
        return value / norm

    def protect(self, anchor: Vector) -> EnclaveProtectedVector:
        value = as_vector(anchor, allow_empty=False, name="anchor vector")
        ciphertext = self._engine.encrypt_normalized(
            self._normalize(value, "anchor vector").tolist()
        )
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise RuntimeError("local OpenFHE engine returned an invalid ciphertext")
        if self._engine.ciphertext_dimension(ciphertext) != value.size:
            raise RuntimeError("local OpenFHE ciphertext dimension is inconsistent")
        return EnclaveProtectedVector(
            provider_id=self.provider_id,
            key_id=self.key_id,
            ciphertext=ciphertext,
            shape=value.shape,
        )

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        if not isinstance(protected_anchor, EnclaveProtectedVector):
            raise TypeError("LocalOpenFheCryptoShield expects EnclaveProtectedVector")
        if (
            protected_anchor.provider_id != self.provider_id
            or protected_anchor.key_id != self.key_id
        ):
            raise ValueError("protected vector belongs to another local OpenFHE key")
        query = as_vector(intent, allow_empty=False, name="intent vector")
        if query.shape != protected_anchor.shape:
            raise ValueError(
                f"dimension mismatch: expected {protected_anchor.shape}, got {query.shape}"
            )
        if self._engine.ciphertext_dimension(protected_anchor.ciphertext) != query.size:
            raise ValueError("local OpenFHE ciphertext dimension is inconsistent")
        result = self._engine.cosine_similarity(
            self._normalize(query, "intent vector").tolist(),
            protected_anchor.ciphertext,
        )
        if isinstance(result, bool) or not isinstance(result, (int, float)):
            raise TypeError("local OpenFHE similarity must return a finite number")
        score = float(result)
        if not math.isfinite(score) or not -1.0001 <= score <= 1.0001:
            raise ValueError("local OpenFHE returned an invalid cosine score")
        return max(-1.0, min(1.0, score))


class EnclaveCryptoShield:
    """Fail-closed adapter for a remotely attested CKKS enclave service.

    Echo Veil deliberately does not emulate an enclave in Python. Construction
    succeeds only when a deployment verifier accepts fresh attestation evidence
    binding the provider to CKKS similarity, hardware isolation, and a ZKP
    access gate. The proof is then exchanged for the opaque provider session
    used by every cryptographic operation.
    """

    algorithm = "CKKS"
    production_ready = True

    def __init__(
        self,
        provider: EnclaveProvider,
        verifier: AttestationVerifier,
        proof_provider: ZeroKnowledgeProofProvider,
        *,
        minimum_security_bits: int = 128,
    ) -> None:
        if (
            isinstance(minimum_security_bits, bool)
            or not isinstance(minimum_security_bits, int)
            or minimum_security_bits < 128
        ):
            raise ValueError("minimum_security_bits must be at least 128")
        nonce = os.urandom(32)
        evidence = provider.attest(nonce)
        if not isinstance(evidence, bytes) or not evidence:
            raise RuntimeError("enclave provider returned invalid attestation evidence")
        verified = verifier.verify(evidence, nonce)
        if not isinstance(verified, VerifiedEnclave):
            raise TypeError("attestation verifier must return VerifiedEnclave")
        if verified.expires_at <= time.time():
            raise RuntimeError("enclave attestation is expired")
        if verified.ckks_security_bits < minimum_security_bits:
            raise RuntimeError("enclave CKKS security level is below policy")
        if not (
            verified.hardware_isolation
            and verified.zkp_access_gate
            and verified.homomorphic_similarity
        ):
            raise RuntimeError(
                "attested provider lacks CKKS homomorphic similarity, hardware "
                "isolation, or the ZKP access gate"
            )
        provider.bind_attestation(verified)
        challenge = provider.access_challenge()
        proof = proof_provider.prove(challenge, verified)
        if not isinstance(proof, bytes) or not proof:
            raise RuntimeError("ZKP proof provider returned an invalid proof")
        session = provider.open_session(proof)
        if not isinstance(session, str) or not session:
            raise RuntimeError("enclave provider rejected the ZKP proof")
        self._provider = provider
        self._verified = verified
        self._session = session

    @property
    def attestation(self) -> VerifiedEnclave:
        return self._verified

    def protect(self, anchor: Vector) -> EnclaveProtectedVector:
        self._ensure_attestation_fresh()
        value = as_vector(anchor, allow_empty=False, name="anchor vector")
        ciphertext = self._provider.encrypt_vector(self._session, value)
        if not isinstance(ciphertext, bytes) or not ciphertext:
            raise RuntimeError("enclave provider returned an invalid CKKS ciphertext")
        return EnclaveProtectedVector(
            provider_id=self._verified.provider_id,
            key_id=self._verified.key_id,
            ciphertext=ciphertext,
            shape=value.shape,
        )

    def similarity(self, intent: Vector, protected_anchor: object) -> float:
        self._ensure_attestation_fresh()
        if not isinstance(protected_anchor, EnclaveProtectedVector):
            raise TypeError("EnclaveCryptoShield expects EnclaveProtectedVector")
        if (
            protected_anchor.provider_id != self._verified.provider_id
            or protected_anchor.key_id != self._verified.key_id
        ):
            raise ValueError("protected vector belongs to another enclave key")
        query = as_vector(intent, allow_empty=False, name="intent vector")
        if query.shape != protected_anchor.shape:
            raise ValueError(
                f"dimension mismatch: expected {protected_anchor.shape}, got {query.shape}"
            )
        result = self._provider.cosine_similarity(
            self._session, query, protected_anchor.ciphertext
        )
        if isinstance(result, bool) or not isinstance(result, (int, float)):
            raise TypeError("enclave similarity must return a finite number")
        score = float(result)
        if not np.isfinite(score) or not -1.0 <= score <= 1.0:
            raise ValueError("enclave similarity returned an invalid cosine score")
        return score

    def _ensure_attestation_fresh(self) -> None:
        if self._verified.expires_at <= time.time():
            raise RuntimeError(
                "enclave attestation expired; create a fresh shield session"
            )
