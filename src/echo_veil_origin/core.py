"""Stateful, fail-closed implementation of the enclave application protocol."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import math
import os
import secrets
import stat
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

from echo_veil.attestation_binding import build_attestation_runtime_data

from ._json import require_exact_keys, strict_json_loads

MAX_VECTOR_ELEMENTS = 16_384
MAX_ENVELOPE_FIELD_BYTES = 20 * 1024 * 1024
MAX_OUTSTANDING_CHALLENGES = 10_000
MAX_ACTIVE_SESSIONS = 10_000
MAX_REPLAY_CACHE_ENTRIES = 50_000
ENVELOPE_INFO = b"echo-veil-cloudflare-envelope-v1:"
CKKS_WRAPPER_INFO = b"echo-veil-authenticated-ckks-wrapper-v1"


class ProtocolError(RuntimeError):
    """A request failed protocol validation without exposing sensitive detail."""


class CkksEngine(Protocol):
    key_id: str

    def encrypt_normalized(self, vector: Sequence[float]) -> bytes:
        raise NotImplementedError

    def cosine_similarity(
        self, normalized_intent: Sequence[float], ciphertext: bytes
    ) -> float:
        raise NotImplementedError

    def ciphertext_dimension(self, ciphertext: bytes) -> int:
        raise NotImplementedError


class ProofVerifier(Protocol):
    def verify(self, proof: bytes, config: OriginConfig) -> VerifiedProof:
        raise NotImplementedError


class NativeEvidenceProvider(Protocol):
    def evidence(self, runtime_data: bytes) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True)
class VerifiedProof:
    challenge: bytes
    public_key: bytes


@dataclass(frozen=True)
class _ChallengeBinding:
    expires_at: float
    profile: str
    scope: str


@dataclass(frozen=True)
class _SessionBinding:
    expires_at: float
    profile: str
    scope: str
    proof_public_key: bytes


def _decode_base64(value: object, field: str, *, maximum: int) -> bytes:
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"invalid {field}")
    try:
        encoded = value.encode("ascii")
        decoded = base64.b64decode(encoded, altchars=b"-_", validate=True)
    except Exception as exc:
        raise ProtocolError(f"invalid {field}") from exc
    if (
        not decoded
        or len(decoded) > maximum
        or not hmac.compare_digest(base64.urlsafe_b64encode(decoded), encoded)
    ):
        raise ProtocolError(f"invalid {field}")
    return decoded


def _encode_base64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def _bounded_binding(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 128
        or any(not 33 <= ord(character) <= 126 for character in value)
    ):
        raise ProtocolError(f"invalid {label}")
    return value


def _read_secret(path: Path, expected_bytes: int, label: str) -> bytes:
    raw = _read_owner_only_file(path, maximum=512, label=label).strip()
    try:
        decoded = base64.b64decode(raw, altchars=b"-_", validate=True)
    except Exception as exc:
        raise RuntimeError(f"{label} file is not valid base64") from exc
    if len(decoded) != expected_bytes:
        raise RuntimeError(f"{label} must decode to {expected_bytes} bytes")
    return decoded


def _read_owner_only_file(path: Path, *, maximum: int, label: str) -> bytes:
    candidate = path.expanduser().absolute()
    if any(component.is_symlink() for component in (candidate, *candidate.parents)):
        raise RuntimeError(f"{label} file path must not contain symbolic links")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(candidate, flags)
    except OSError as exc:
        raise RuntimeError(f"{label} file is missing or unreadable") from exc
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise RuntimeError(f"{label} file must be regular")
        if os.name == "posix" and stat.S_IMODE(info.st_mode) & 0o077:
            raise RuntimeError(f"{label} file permissions must be 0600 or stricter")
        if info.st_size > maximum:
            raise RuntimeError(f"{label} file exceeds the safety limit")
        raw = bytearray()
        while len(raw) <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not chunk:
                break
            raw.extend(chunk)
    finally:
        os.close(descriptor)
    if len(raw) > maximum:
        raise RuntimeError(f"{label} file exceeds the safety limit")
    return bytes(raw)


@dataclass(frozen=True)
class OriginConfig:
    provider_id: str
    measurement: str
    key_id: str
    cce_policy_hash: str
    maa_policy_hash: str
    workload_digest: str
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
            ("cce_policy_hash", self.cce_policy_hash),
            ("maa_policy_hash", self.maa_policy_hash),
            ("workload_digest", self.workload_digest),
            ("region", self.region),
        ):
            if (
                not isinstance(string_value, str)
                or not string_value
                or string_value != string_value.strip()
                or len(string_value) > 512
                or not string_value.isprintable()
                or any(character.isspace() for character in string_value)
            ):
                raise ValueError(f"{label} must be a non-empty bounded string")
        for label, duration_value in (
            ("challenge_ttl_seconds", self.challenge_ttl_seconds),
            ("session_ttl_seconds", self.session_ttl_seconds),
            ("attestation_ttl_seconds", self.attestation_ttl_seconds),
        ):
            if (
                isinstance(duration_value, bool)
                or not isinstance(duration_value, (int, float))
                or not math.isfinite(float(duration_value))
                or not 0.0 < float(duration_value) <= 600.0
            ):
                raise ValueError(f"{label} must be within (0, 600]")
        if (
            isinstance(self.maximum_vector_elements, bool)
            or not isinstance(self.maximum_vector_elements, int)
            or not 1 <= self.maximum_vector_elements <= MAX_VECTOR_ELEMENTS
        ):
            raise ValueError("maximum_vector_elements is outside the safety limit")


class AttestationSigner:
    """Issue normalized claims with a key released only to the approved CVM."""

    def __init__(
        self,
        signing_key: Ed25519PrivateKey,
        transport_public_key: bytes,
        config: OriginConfig,
        native_evidence_provider: NativeEvidenceProvider,
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
        self._native_evidence_provider = native_evidence_provider

    @classmethod
    def from_secret_file(
        cls,
        signing_key_file: str | os.PathLike[str],
        transport_public_key: bytes,
        config: OriginConfig,
        native_evidence_provider: NativeEvidenceProvider,
    ) -> AttestationSigner:
        raw = _read_secret(Path(signing_key_file), 32, "attestation signing key")
        return cls(
            Ed25519PrivateKey.from_private_bytes(raw),
            transport_public_key,
            config,
            native_evidence_provider,
        )

    def issue(self, nonce: bytes) -> bytes:
        if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 256:
            raise ProtocolError("invalid attestation nonce")
        runtime_data = build_attestation_runtime_data(
            nonce=nonce,
            transport_public_key=self._transport_public_key,
            provider_id=self._config.provider_id,
            measurement=self._config.measurement,
            key_id=self._config.key_id,
            cce_policy_hash=self._config.cce_policy_hash,
            maa_policy_hash=self._config.maa_policy_hash,
            workload_digest=self._config.workload_digest,
        )
        try:
            native_evidence = self._native_evidence_provider.evidence(runtime_data)
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("native attestation evidence is unavailable") from exc
        if (
            not isinstance(native_evidence, bytes)
            or not 0 < len(native_evidence) <= 65_536
        ):
            raise ProtocolError("native attestation evidence is invalid")
        issued_at = time.time()
        claims = json.dumps(
            {
                "attestation_authority": "microsoft-azure-attestation+secure-key-release-v1",
                "cce_policy_hash": self._config.cce_policy_hash,
                "ckks_security_bits": 128,
                "expires_at": issued_at + self._config.attestation_ttl_seconds,
                "hardware_isolation": True,
                "homomorphic_similarity": True,
                "issued_at": issued_at,
                "key_id": self._config.key_id,
                "measurement": self._config.measurement,
                "maa_policy_hash": self._config.maa_policy_hash,
                "native_evidence_b64": _encode_base64(native_evidence),
                "nonce_b64": _encode_base64(nonce),
                "platform": "azure-amd-sev-snp-confidential-vm",
                "provider_id": self._config.provider_id,
                "region": self._config.region,
                "runtime_binding_b64": _encode_base64(runtime_data),
                "transport_public_key_b64": _encode_base64(self._transport_public_key),
                "workload_digest": self._config.workload_digest,
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
        if attestation_signer._config != config:
            raise RuntimeError(
                "attestation signer config does not match enclave config"
            )
        expected_transport_key = self.transport_public_key(transport_key)
        if not hmac.compare_digest(
            attestation_signer._transport_public_key, expected_transport_key
        ):
            raise RuntimeError(
                "attestation signer transport key does not match enclave transport key"
            )
        self.config = config
        self._transport_key = transport_key
        self._attestation_signer = attestation_signer
        self._proof_verifier = proof_verifier
        self._ckks = ckks
        transport_secret = transport_key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
        self._ckks_wrapper_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=hashlib.sha256(config.key_id.encode("utf-8")).digest(),
            info=CKKS_WRAPPER_INFO,
        ).derive(transport_secret)
        self._challenges: dict[bytes, _ChallengeBinding] = {}
        self._sessions: dict[str, _SessionBinding] = {}
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
        try:
            require_exact_keys(dict(request), {"nonce_b64"})
        except ValueError as exc:
            raise ProtocolError("invalid attestation request") from exc
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
        try:
            require_exact_keys(
                dict(envelope),
                {"ephemeral_public_key_b64", "nonce_b64", "ciphertext_b64"},
            )
        except ValueError as exc:
            raise ProtocolError("invalid request envelope") from exc
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
        try:
            ephemeral = X25519PublicKey.from_public_bytes(ephemeral_bytes)
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=nonce,
                info=ENVELOPE_INFO + path.encode("ascii"),
            ).derive(self._transport_key.exchange(ephemeral))
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, path.encode("ascii"))
            request = strict_json_loads(plaintext)
            if not isinstance(request, dict):
                raise ValueError
        except ProtocolError:
            raise
        except Exception as exc:
            raise ProtocolError("request envelope authentication failed") from exc
        self._validate_request_schema(path, request)
        with self._lock:
            self._purge(now)
            if replay_key in self._seen_envelopes:
                raise ProtocolError("request envelope replayed")
            if len(self._seen_envelopes) >= MAX_REPLAY_CACHE_ENTRIES:
                raise ProtocolError("request replay cache is at capacity")
            self._seen_envelopes[replay_key] = now + 600.0
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
            profile = _bounded_binding(request.get("profile"), "profile")
            scope = _bounded_binding(request.get("scope"), "scope")
            challenge = os.urandom(32)
            with self._lock:
                self._purge(time.time())
                if len(self._challenges) >= MAX_OUTSTANDING_CHALLENGES:
                    raise ProtocolError("challenge capacity reached")
                self._challenges[challenge] = _ChallengeBinding(
                    expires_at=time.time() + self.config.challenge_ttl_seconds,
                    profile=profile,
                    scope=scope,
                )
            return {"challenge_b64": _encode_base64(challenge)}
        if path == "/v1/session":
            profile = _bounded_binding(request.get("profile"), "profile")
            scope = _bounded_binding(request.get("scope"), "scope")
            proof = _decode_base64(request.get("proof_b64"), "proof_b64", maximum=4096)
            try:
                verified_proof = self._proof_verifier.verify(proof, self.config)
            except ProtocolError:
                raise
            except Exception as exc:
                raise ProtocolError("zero-knowledge proof rejected") from exc
            if (
                not isinstance(verified_proof, VerifiedProof)
                or not isinstance(verified_proof.challenge, bytes)
                or not 32 <= len(verified_proof.challenge) <= 256
                or not isinstance(verified_proof.public_key, bytes)
                or len(verified_proof.public_key) != 32
            ):
                raise ProtocolError("proof verifier returned an invalid challenge")
            with self._lock:
                now = time.time()
                self._purge(now)
                challenge_binding = self._challenges.pop(verified_proof.challenge, None)
                if (
                    challenge_binding is None
                    or challenge_binding.expires_at <= now
                    or challenge_binding.profile != profile
                    or challenge_binding.scope != scope
                ):
                    raise ProtocolError(
                        "proof challenge is unknown, expired, consumed, or misbound"
                    )
                if len(self._sessions) >= MAX_ACTIVE_SESSIONS:
                    raise ProtocolError("session capacity reached")
                new_session = secrets.token_urlsafe(32)
                self._sessions[new_session] = _SessionBinding(
                    expires_at=now + self.config.session_ttl_seconds,
                    profile=profile,
                    scope=scope,
                    proof_public_key=verified_proof.public_key,
                )
            return {"session": new_session}
        session_value = request.get("session")
        if (
            not isinstance(session_value, str)
            or not 0 < len(session_value) <= 4_096
            or any(not 33 <= ord(character) <= 126 for character in session_value)
        ):
            raise ProtocolError("invalid or expired enclave session")
        session = self._session(session_value)
        if path == "/v1/vector/encrypt":
            vector = self._vector(request.get("vector"), "vector")
            normalized = self._normalize(vector)
            try:
                ciphertext = self._ckks.encrypt_normalized(normalized)
            except Exception as exc:
                raise ProtocolError("CKKS encryption failed") from exc
            if (
                not isinstance(ciphertext, bytes)
                or not 0 < len(ciphertext) <= 16 * 1024 * 1024
            ):
                raise ProtocolError("CKKS engine returned an invalid ciphertext")
            try:
                if self._ckks.ciphertext_dimension(ciphertext) != len(normalized):
                    raise ProtocolError("CKKS engine returned a dimension mismatch")
            except ProtocolError:
                raise
            except Exception as exc:
                raise ProtocolError("CKKS encryption validation failed") from exc
            return {
                "ciphertext_b64": _encode_base64(
                    self._wrap_ckks_ciphertext(ciphertext, len(normalized), session)
                )
            }
        if path == "/v1/vector/similarity":
            intent = self._vector(request.get("intent"), "intent")
            wrapped_ciphertext = _decode_base64(
                request.get("ciphertext_b64"),
                "ciphertext_b64",
                maximum=16 * 1024 * 1024,
            )
            dimension, ciphertext = self._unwrap_ckks_ciphertext(
                wrapped_ciphertext, session
            )
            try:
                if dimension != len(intent):
                    raise ProtocolError("vector dimension mismatch")
                if self._ckks.ciphertext_dimension(ciphertext) != dimension:
                    raise ProtocolError("vector dimension mismatch")
                score = float(
                    self._ckks.cosine_similarity(self._normalize(intent), ciphertext)
                )
            except ProtocolError:
                raise
            except Exception as exc:
                raise ProtocolError("CKKS similarity failed") from exc
            if not math.isfinite(score) or not -1.0001 <= score <= 1.0001:
                raise ProtocolError("CKKS engine returned an invalid similarity")
            return {"score": max(-1.0, min(1.0, score))}
        raise ProtocolError("unsupported enclave path")

    @staticmethod
    def _validate_request_schema(
        path: str,
        request: Mapping[str, object],
    ) -> None:
        expected_fields = {
            "/v1/challenge": {"profile", "scope"},
            "/v1/session": {"proof_b64", "profile", "scope"},
            "/v1/vector/encrypt": {"session", "vector"},
            "/v1/vector/similarity": {"session", "intent", "ciphertext_b64"},
        }.get(path)
        if expected_fields is None:
            raise ProtocolError("unsupported enclave path")
        try:
            require_exact_keys(dict(request), expected_fields)
        except ValueError as exc:
            raise ProtocolError("invalid enclave request schema") from exc

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

    def _session(self, value: str) -> _SessionBinding:
        now = time.time()
        with self._lock:
            self._purge(now)
            binding = self._sessions.get(value)
            if binding is None or binding.expires_at <= now:
                raise ProtocolError("invalid or expired enclave session")
            return binding

    def _wrap_ckks_ciphertext(
        self,
        ciphertext: bytes,
        dimension: int,
        session: _SessionBinding,
    ) -> bytes:
        authenticated = {
            "ciphertext_b64": _encode_base64(ciphertext),
            "dimension": dimension,
            "format": "echo-veil-authenticated-ckks-v1",
            "key_id": self.config.key_id,
            "profile": session.profile,
            "proof_public_key_b64": _encode_base64(session.proof_public_key),
            "scope": session.scope,
        }
        serialized = json.dumps(
            authenticated, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        authenticated["tag_b64"] = _encode_base64(
            hmac.new(self._ckks_wrapper_key, serialized, hashlib.sha256).digest()
        )
        return json.dumps(authenticated, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )

    def _unwrap_ckks_ciphertext(
        self,
        wrapped: bytes,
        session: _SessionBinding,
    ) -> tuple[int, bytes]:
        try:
            value = strict_json_loads(wrapped)
            if not isinstance(value, dict):
                raise ValueError
            require_exact_keys(
                value,
                {
                    "ciphertext_b64",
                    "dimension",
                    "format",
                    "key_id",
                    "profile",
                    "proof_public_key_b64",
                    "scope",
                    "tag_b64",
                },
            )
            tag = _decode_base64(value.pop("tag_b64"), "tag_b64", maximum=32)
            if len(tag) != 32:
                raise ValueError
            serialized = json.dumps(
                value, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
            expected_tag = hmac.new(
                self._ckks_wrapper_key, serialized, hashlib.sha256
            ).digest()
            if not hmac.compare_digest(tag, expected_tag):
                raise ValueError
            if value.get("format") != "echo-veil-authenticated-ckks-v1":
                raise ValueError
            if value.get("key_id") != self.config.key_id:
                raise ValueError
            if value.get("profile") != session.profile:
                raise ValueError
            if value.get("scope") != session.scope:
                raise ValueError
            public_key = _decode_base64(
                value.get("proof_public_key_b64"),
                "proof_public_key_b64",
                maximum=32,
            )
            if not hmac.compare_digest(public_key, session.proof_public_key):
                raise ValueError
            dimension = value.get("dimension")
            if (
                isinstance(dimension, bool)
                or not isinstance(dimension, int)
                or not 0 < dimension <= self.config.maximum_vector_elements
            ):
                raise ValueError
            ciphertext = _decode_base64(
                value.get("ciphertext_b64"),
                "ciphertext_b64",
                maximum=16 * 1024 * 1024,
            )
        except Exception as exc:
            raise ProtocolError("CKKS ciphertext authentication failed") from exc
        return dimension, ciphertext

    def _purge(self, now: float) -> None:
        self._challenges = {
            key: binding
            for key, binding in self._challenges.items()
            if binding.expires_at > now
        }
        self._sessions = {
            key: binding
            for key, binding in self._sessions.items()
            if binding.expires_at > now
        }
        self._seen_envelopes = {
            key: expiry for key, expiry in self._seen_envelopes.items() if expiry > now
        }


def origin_token_matches(expected: str, authorization: str | None) -> bool:
    """Compare a Worker-to-origin bearer token without timing leakage."""
    if not expected or not authorization or not authorization.startswith("Bearer "):
        return False
    supplied = authorization.removeprefix("Bearer ")
    if len(supplied) != len(expected):
        return False
    return hmac.compare_digest(expected.encode(), supplied.encode())
