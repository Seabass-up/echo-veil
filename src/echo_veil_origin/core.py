"""Stateful, fail-closed implementation of the enclave application protocol."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAX_VECTOR_ELEMENTS = 16_384
MAX_ENVELOPE_FIELD_BYTES = 20 * 1024 * 1024
MAX_OUTSTANDING_CHALLENGES = 10_000
MAX_ACTIVE_SESSIONS = 10_000
MAX_REPLAY_CACHE_ENTRIES = 50_000
ENVELOPE_INFO = b"echo-veil-cloudflare-envelope-v1:"


class ProtocolError(RuntimeError):
    """A request failed protocol validation without exposing sensitive detail."""


class CkksEngine(Protocol):
    key_id: str

    def encrypt_normalized(self, vector: Sequence[float]) -> bytes: ...

    def cosine_similarity(
        self, normalized_intent: Sequence[float], ciphertext: bytes
    ) -> float: ...

    def ciphertext_dimension(self, ciphertext: bytes) -> int: ...


class ProofVerifier(Protocol):
    def verify(self, proof: bytes, config: OriginConfig) -> bytes: ...


def _decode_base64(value: object, field: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"invalid {field}")
    try:
        decoded = base64.b64decode(value.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ProtocolError(f"invalid {field}") from exc
    if not decoded or len(decoded) > maximum:
        raise ProtocolError(f"invalid {field}")
    return decoded


def _encode_base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _read_secret(path: Path, expected_bytes: int, label: str) -> bytes:
    if not path.is_file():
        raise RuntimeError(f"{label} file is missing")
    if os.name == "posix" and path.stat().st_mode & 0o077:
        raise RuntimeError(f"{label} file permissions must be 0600 or stricter")
    raw = path.read_bytes().strip()
    try:
        decoded = base64.b64decode(raw, altchars=b"-_", validate=True)
    except Exception as exc:
        raise RuntimeError(f"{label} file is not valid base64") from exc
    if len(decoded) != expected_bytes:
        raise RuntimeError(f"{label} must decode to {expected_bytes} bytes")
    return decoded


@dataclass(frozen=True)
class OriginConfig:
    provider_id: str
    measurement: str
    key_id: str
    region: str = "eastus2"
    challenge_ttl_seconds: float = 60.0
    session_ttl_seconds: float = 300.0
    attestation_ttl_seconds: float = 120.0
    maximum_vector_elements: int = MAX_VECTOR_ELEMENTS

    def __post_init__(self) -> None:
        for label, string_value in (
            ("provider_id", self.provider_id),
            ("measurement", self.measurement),
            ("key_id", self.key_id),
            ("region", self.region),
        ):
            if (
                not isinstance(string_value, str)
                or not string_value
                or len(string_value) > 512
            ):
                raise ValueError(f"{label} must be a non-empty bounded string")
        for label, duration_value in (
            ("challenge_ttl_seconds", self.challenge_ttl_seconds),
            ("session_ttl_seconds", self.session_ttl_seconds),
            ("attestation_ttl_seconds", self.attestation_ttl_seconds),
        ):
            if not math.isfinite(duration_value) or not 0.0 < duration_value <= 600.0:
                raise ValueError(f"{label} must be within (0, 600]")
        if not 1 <= self.maximum_vector_elements <= MAX_VECTOR_ELEMENTS:
            raise ValueError("maximum_vector_elements is outside the safety limit")


class AttestationSigner:
    """Issue normalized claims with a key released only to the approved CVM."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        transport_public_key: bytes,
        config: OriginConfig,
    ) -> None:
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError("signing_key must be Ed25519PrivateKey")
        if (
            not isinstance(transport_public_key, bytes)
            or len(transport_public_key) != 32
        ):
            raise ValueError("transport public key must be 32 bytes")
        self._signing_key = signing_key
        self._transport_public_key = transport_public_key
        self._config = config

    @classmethod
    def from_secret_file(
        cls,
        signing_key_file: str | os.PathLike[str],
        transport_public_key: bytes,
        config: OriginConfig,
    ) -> AttestationSigner:
        raw = _read_secret(Path(signing_key_file), 32, "attestation signing key")
        return cls(
            Ed25519PrivateKey.from_private_bytes(raw), transport_public_key, config
        )

    def issue(self, nonce: bytes) -> bytes:
        if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 256:
            raise ProtocolError("invalid attestation nonce")
        issued_at = time.time()
        claims = json.dumps(
            {
                "attestation_authority": "azure-key-vault-secure-key-release",
                "ckks_security_bits": 128,
                "expires_at": issued_at + self._config.attestation_ttl_seconds,
                "hardware_isolation": True,
                "homomorphic_similarity": True,
                "issued_at": issued_at,
                "key_id": self._config.key_id,
                "measurement": self._config.measurement,
                "nonce_b64": _encode_base64(nonce),
                "platform": "azure-amd-sev-snp-confidential-vm",
                "provider_id": self._config.provider_id,
                "region": self._config.region,
                "transport_public_key_b64": _encode_base64(self._transport_public_key),
                "zkp_access_gate": True,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return json.dumps(
            {
                "payload_b64": _encode_base64(claims),
                "signature_b64": _encode_base64(self._signing_key.sign(claims)),
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


class EnclaveService:
    """Own transport keys, one-time challenges, sessions, and CKKS operations."""

    def __init__(
        self,
        config: OriginConfig,
        transport_key: X25519PrivateKey,
        attestation_signer: AttestationSigner,
        proof_verifier: ProofVerifier,
        ckks: CkksEngine,
    ) -> None:
        if ckks.key_id != config.key_id:
            raise RuntimeError("CKKS engine key ID does not match attestation config")
        self.config = config
        self._transport_key = transport_key
        self._attestation_signer = attestation_signer
        self._proof_verifier = proof_verifier
        self._ckks = ckks
        self._challenges: dict[bytes, float] = {}
        self._sessions: dict[str, float] = {}
        self._seen_envelopes: dict[bytes, float] = {}
        self._lock = threading.RLock()

    @classmethod
    def transport_key_from_secret_file(
        cls, path: str | os.PathLike[str]
    ) -> X25519PrivateKey:
        raw = _read_secret(Path(path), 32, "transport private key")
        return X25519PrivateKey.from_private_bytes(raw)

    @staticmethod
    def transport_public_key(transport_key: X25519PrivateKey) -> bytes:
        return transport_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def attest(self, request: Mapping[str, object]) -> dict[str, str]:
        nonce = _decode_base64(request.get("nonce_b64"), "nonce_b64", maximum=256)
        return {"evidence_b64": _encode_base64(self._attestation_signer.issue(nonce))}

    def health(self) -> dict[str, object]:
        return {
            "ready": True,
            "provider_id": self.config.provider_id,
            "key_id": self.config.key_id,
            "platform": "azure-amd-sev-snp-confidential-vm",
            "ckks": True,
            "zkp": True,
        }

    def process_envelope(
        self, path: str, envelope: Mapping[str, object]
    ) -> dict[str, str]:
        if path not in {
            "/v1/challenge",
            "/v1/session",
            "/v1/vector/encrypt",
            "/v1/vector/similarity",
        }:
            raise ProtocolError("unsupported enclave path")
        ephemeral_bytes = _decode_base64(
            envelope.get("ephemeral_public_key_b64"),
            "ephemeral_public_key_b64",
            maximum=32,
        )
        nonce = _decode_base64(envelope.get("nonce_b64"), "nonce_b64", maximum=12)
        ciphertext = _decode_base64(
            envelope.get("ciphertext_b64"),
            "ciphertext_b64",
            maximum=MAX_ENVELOPE_FIELD_BYTES,
        )
        if len(ephemeral_bytes) != 32 or len(nonce) != 12:
            raise ProtocolError("invalid envelope key or nonce")
        now = time.time()
        replay_key = hashlib.sha256(ephemeral_bytes + nonce).digest()
        with self._lock:
            self._purge(now)
            if replay_key in self._seen_envelopes:
                raise ProtocolError("request envelope replayed")
            if len(self._seen_envelopes) >= MAX_REPLAY_CACHE_ENTRIES:
                raise ProtocolError("request replay cache is at capacity")
            self._seen_envelopes[replay_key] = now + 600.0
        try:
            ephemeral = X25519PublicKey.from_public_bytes(ephemeral_bytes)
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=nonce,
                info=ENVELOPE_INFO + path.encode("ascii"),
            ).derive(self._transport_key.exchange(ephemeral))
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, path.encode("ascii"))
            request = json.loads(plaintext.decode("utf-8"))
            if not isinstance(request, dict):
                raise ValueError
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("request envelope authentication failed") from exc
        response = self._dispatch(path, request)
        response_plaintext = json.dumps(
            response, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        response_nonce = os.urandom(12)
        response_ciphertext = AESGCM(key).encrypt(
            response_nonce,
            response_plaintext,
            path.encode("ascii") + b":response",
        )
        return {
            "nonce_b64": _encode_base64(response_nonce),
            "ciphertext_b64": _encode_base64(response_ciphertext),
        }

    def _dispatch(self, path: str, request: Mapping[str, object]) -> dict[str, object]:
        if path == "/v1/challenge":
            if request:
                raise ProtocolError("challenge request must be empty")
            challenge = os.urandom(32)
            with self._lock:
                self._purge(time.time())
                if len(self._challenges) >= MAX_OUTSTANDING_CHALLENGES:
                    raise ProtocolError("challenge capacity reached")
                self._challenges[challenge] = (
                    time.time() + self.config.challenge_ttl_seconds
                )
            return {"challenge_b64": _encode_base64(challenge)}
        if path == "/v1/session":
            proof = _decode_base64(request.get("proof_b64"), "proof_b64", maximum=4096)
            challenge = self._proof_verifier.verify(proof, self.config)
            with self._lock:
                now = time.time()
                self._purge(now)
                expiry = self._challenges.pop(challenge, None)
                if expiry is None or expiry <= now:
                    raise ProtocolError(
                        "proof challenge is unknown, expired, or consumed"
                    )
                if len(self._sessions) >= MAX_ACTIVE_SESSIONS:
                    raise ProtocolError("session capacity reached")
                new_session = secrets.token_urlsafe(32)
                self._sessions[new_session] = now + self.config.session_ttl_seconds
            return {"session": new_session}
        session_value = request.get("session")
        if not isinstance(session_value, str) or not self._valid_session(session_value):
            raise ProtocolError("invalid or expired enclave session")
        if path == "/v1/vector/encrypt":
            vector = self._vector(request.get("vector"), "vector")
            normalized = self._normalize(vector)
            ciphertext = self._ckks.encrypt_normalized(normalized)
            return {"ciphertext_b64": _encode_base64(ciphertext)}
        if path == "/v1/vector/similarity":
            intent = self._vector(request.get("intent"), "intent")
            ciphertext = _decode_base64(
                request.get("ciphertext_b64"),
                "ciphertext_b64",
                maximum=16 * 1024 * 1024,
            )
            if self._ckks.ciphertext_dimension(ciphertext) != len(intent):
                raise ProtocolError("vector dimension mismatch")
            score = float(
                self._ckks.cosine_similarity(self._normalize(intent), ciphertext)
            )
            if not math.isfinite(score) or not -1.0001 <= score <= 1.0001:
                raise ProtocolError("CKKS engine returned an invalid similarity")
            return {"score": max(-1.0, min(1.0, score))}
        raise ProtocolError("unsupported enclave path")

    def _vector(self, value: object, label: str) -> list[float]:
        if (
            not isinstance(value, Sequence)
            or isinstance(value, (str, bytes, bytearray))
            or not 0 < len(value) <= self.config.maximum_vector_elements
        ):
            raise ProtocolError(f"invalid {label}")
        output: list[float] = []
        for part in value:
            if isinstance(part, bool) or not isinstance(part, (int, float)):
                raise ProtocolError(f"invalid {label}")
            number = float(part)
            if not math.isfinite(number):
                raise ProtocolError(f"invalid {label}")
            output.append(number)
        return output

    @staticmethod
    def _normalize(vector: Sequence[float]) -> list[float]:
        norm = math.sqrt(sum(value * value for value in vector))
        if not math.isfinite(norm) or norm <= 1e-15:
            raise ProtocolError("zero-norm vectors are not supported")
        return [value / norm for value in vector]

    def _valid_session(self, value: str) -> bool:
        now = time.time()
        with self._lock:
            self._purge(now)
            expiry = self._sessions.get(value)
            return expiry is not None and expiry > now

    def _purge(self, now: float) -> None:
        self._challenges = {
            key: expiry for key, expiry in self._challenges.items() if expiry > now
        }
        self._sessions = {
            key: expiry for key, expiry in self._sessions.items() if expiry > now
        }
        self._seen_envelopes = {
            key: expiry for key, expiry in self._seen_envelopes.items() if expiry > now
        }


def origin_token_matches(expected: str, authorization: str | None) -> bool:
    """Compare a Worker-to-origin bearer token without timing leakage."""
    if not expected or not authorization or not authorization.startswith("Bearer "):
        return False
    supplied = authorization.removeprefix("Bearer ")
    return hmac.compare_digest(expected.encode(), supplied.encode())
