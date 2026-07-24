from __future__ import annotations

import base64
import json
import time

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_veil import (
    AesGcmCryptoShield,
    EnclaveCryptoShield,
    EnclaveProtectedVector,
    Ed25519AttestationVerifier,
    LocalOpenFheCryptoShield,
    Oracle,
    VerifiedEnclave,
)
from echo_veil.crypto_shield import ProtectedVector


class _TestEnclaveProvider:
    def attest(self, nonce: bytes) -> bytes:
        self.nonce = nonce
        return b"vendor-evidence:" + nonce

    def access_challenge(self) -> bytes:
        return b"a" * 32

    def bind_attestation(self, enclave: VerifiedEnclave) -> None:
        self.enclave = enclave

    def open_session(self, proof: bytes) -> str:
        return "session" if proof == b"valid-proof" else ""

    def encrypt_vector(self, session: str, anchor: np.ndarray) -> bytes:
        assert session == "session"
        return anchor.astype(np.float64).tobytes()

    def cosine_similarity(
        self, session: str, intent: np.ndarray, ciphertext: bytes
    ) -> float:
        assert session == "session"
        anchor = np.frombuffer(ciphertext, dtype=np.float64)
        return float(
            np.dot(intent, anchor) / (np.linalg.norm(intent) * np.linalg.norm(anchor))
        )


class _TestVerifier:
    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedEnclave:
        assert evidence == b"vendor-evidence:" + nonce
        return VerifiedEnclave(
            provider_id="test-enclave",
            measurement="trusted-measurement",
            key_id="sealed-key-1",
            expires_at=time.time() + 60,
            ckks_security_bits=128,
            hardware_isolation=True,
            zkp_access_gate=True,
            homomorphic_similarity=True,
            transport_public_key=b"k" * 32,
        )


class _TestProofProvider:
    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes:
        assert challenge == b"a" * 32
        assert enclave.measurement == "trusted-measurement"
        return b"valid-proof"


class _TestLocalCkksEngine:
    def __init__(self, key_id: str = "local-key-1") -> None:
        self.key_id = key_id

    def encrypt_normalized(self, vector) -> bytes:
        return np.asarray(vector, dtype=np.float64).tobytes()

    def ciphertext_dimension(self, ciphertext: bytes) -> int:
        return len(ciphertext) // np.dtype(np.float64).itemsize

    def cosine_similarity(self, normalized_intent, ciphertext: bytes) -> float:
        anchor = np.frombuffer(ciphertext, dtype=np.float64)
        return float(np.dot(np.asarray(normalized_intent), anchor))


def test_verified_enclave_rejects_whitespace_identifiers() -> None:
    with pytest.raises(ValueError, match="identifiers"):
        VerifiedEnclave(
            provider_id="provider\N{NO-BREAK SPACE}name",
            measurement="measurement",
            key_id="key",
            expires_at=time.time() + 60,
            ckks_security_bits=128,
            hardware_isolation=True,
            zkp_access_gate=True,
            homomorphic_similarity=True,
            transport_public_key=b"k" * 32,
        )


def test_aes_gcm_shield_encrypts_anchor_and_computes_similarity() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    anchor = np.array([1.0, 0.0], dtype=np.float64)

    protected = shield.protect(anchor)

    assert isinstance(protected, ProtectedVector)
    assert protected.algorithm == "AES-256-GCM"
    assert protected.ciphertext != anchor.tobytes()
    assert protected.nonce
    assert protected.shape == (2,)

    assert shield.similarity(np.array([1.0, 0.0]), protected) == pytest.approx(1.0)
    assert shield.similarity(np.array([0.0, 1.0]), protected) == pytest.approx(0.0)


def test_local_openfhe_shield_runs_ckks_without_a_remote_provider() -> None:
    shield = LocalOpenFheCryptoShield(_TestLocalCkksEngine())
    oracle = Oracle(environment="local", shield=shield)

    protected = shield.protect(np.array([3.0, 4.0]))

    assert oracle.environment == "local-private"
    assert protected.provider_id == "local-openfhe"
    assert protected.key_id == "local-key-1"
    assert protected.shape == (2,)
    assert shield.similarity(np.array([3.0, 4.0]), protected) == pytest.approx(1.0)
    assert shield.similarity(np.array([-4.0, 3.0]), protected) == pytest.approx(0.0)
    assert (
        EnclaveProtectedVector.from_json_bytes(protected.to_json_bytes()) == protected
    )


def test_local_openfhe_shield_rejects_invalid_vectors_and_keys() -> None:
    shield = LocalOpenFheCryptoShield(_TestLocalCkksEngine())
    protected = shield.protect(np.array([1.0, 0.0]))

    with pytest.raises(ValueError, match="non-zero"):
        shield.protect(np.array([0.0, 0.0]))
    with pytest.raises(ValueError, match="dimension mismatch"):
        shield.similarity(np.array([1.0, 0.0, 0.0]), protected)
    with pytest.raises(ValueError, match="another local OpenFHE key"):
        LocalOpenFheCryptoShield(_TestLocalCkksEngine("other-key")).similarity(
            np.array([1.0, 0.0]), protected
        )


def test_aes_gcm_shield_rejects_tampered_ciphertext() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    protected = shield.protect(np.array([1.0, 0.0], dtype=np.float64))
    tampered = ProtectedVector(
        algorithm=protected.algorithm,
        nonce=protected.nonce,
        ciphertext=protected.ciphertext[:-1] + bytes([protected.ciphertext[-1] ^ 0x01]),
        shape=protected.shape,
        dtype=protected.dtype,
    )

    with pytest.raises(ValueError, match="decrypt"):
        shield.similarity(np.array([1.0, 0.0]), tampered)


def test_protected_vector_json_roundtrip() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    protected = shield.protect(np.array([1.0, 0.0], dtype=np.float64))

    restored = ProtectedVector.from_json_bytes(protected.to_json_bytes())

    assert restored == protected
    assert shield.similarity(
        np.array([1.0, 0.0], dtype=np.float64), restored
    ) == pytest.approx(1.0)


def test_aes_gcm_shield_key_helpers_and_env_loader(monkeypatch) -> None:
    key = AesGcmCryptoShield.generate_key()
    encoded = AesGcmCryptoShield.key_to_base64(key)
    assert AesGcmCryptoShield.key_from_base64(encoded) == key

    monkeypatch.setenv("ECHO_VEIL_CRYPTO_KEY", encoded)
    shield = AesGcmCryptoShield.from_env()
    protected = shield.protect(np.array([1.0, 0.0], dtype=np.float64))
    assert shield.similarity(np.array([1.0, 0.0]), protected) == pytest.approx(1.0)


def test_aes_gcm_shield_rejects_invalid_key_material() -> None:
    with pytest.raises(ValueError, match="32 bytes"):
        AesGcmCryptoShield(b"short")

    with pytest.raises(ValueError, match="not set"):
        AesGcmCryptoShield.from_env("MISSING_ECHO_VEIL_KEY")

    with pytest.raises(ValueError, match="32 bytes"):
        AesGcmCryptoShield.key_from_base64(base64.urlsafe_b64encode(b"short").decode())

    with pytest.raises(ValueError, match="base64"):
        AesGcmCryptoShield.key_from_base64("not valid base64!")


def test_aes_gcm_shield_rejects_empty_anchor() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())

    with pytest.raises(ValueError, match="empty anchor"):
        shield.protect(np.array([], dtype=np.float64))


def test_protected_vector_rejects_malformed_json_and_payloads() -> None:
    with pytest.raises(ValueError, match="JSON"):
        ProtectedVector.from_json_bytes(b"not json")

    with pytest.raises(ValueError, match="JSON"):
        ProtectedVector.from_json_bytes(json.dumps(["not", "a", "dict"]).encode())

    valid = ProtectedVector(
        algorithm="AES-256-GCM",
        nonce=b"1" * 12,
        ciphertext=b"2" * 16,
        shape=(2,),
        dtype="float64",
    ).as_dict()

    for mutation in (
        {"shape": "2"},
        {"shape": [0]},
        {"shape": [2, 2]},
        {"shape": [True]},
        {"nonce_b64": "not valid base64!"},
        {"nonce_b64": base64.urlsafe_b64encode(b"short").decode("ascii")},
        {"ciphertext_b64": ""},
        {"algorithm": ""},
        {"dtype": ""},
    ):
        payload = dict(valid)
        payload.update(mutation)
        with pytest.raises(ValueError, match="Invalid|base64"):
            ProtectedVector.from_dict(payload)


def test_aes_gcm_shield_rejects_unsupported_protected_metadata() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    protected = shield.protect(np.array([1.0, 0.0], dtype=np.float64))

    wrong_algorithm = ProtectedVector(
        algorithm="OTHER",
        nonce=protected.nonce,
        ciphertext=protected.ciphertext,
        shape=protected.shape,
        dtype=protected.dtype,
    )
    with pytest.raises(ValueError, match="Unsupported"):
        shield.similarity(np.array([1.0, 0.0], dtype=np.float64), wrong_algorithm)

    wrong_dtype = ProtectedVector(
        algorithm=protected.algorithm,
        nonce=protected.nonce,
        ciphertext=protected.ciphertext,
        shape=protected.shape,
        dtype="float32",
    )
    with pytest.raises(ValueError, match="Unsupported"):
        shield.similarity(np.array([1.0, 0.0], dtype=np.float64), wrong_dtype)


def test_aes_gcm_shield_rejects_dimension_mismatch() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    protected = shield.protect(np.array([1.0, 0.0], dtype=np.float64))

    with pytest.raises(ValueError, match="dimension mismatch"):
        shield.similarity(np.array([1.0, 0.0, 0.0], dtype=np.float64), protected)


def test_enclave_crypto_shield_requires_verified_ckks_enclave_and_zkp() -> None:
    shield = EnclaveCryptoShield(
        _TestEnclaveProvider(), _TestVerifier(), _TestProofProvider()
    )
    production_oracle = Oracle(environment="production", shield=shield)
    protected = shield.protect(np.array([1.0, 0.0]))

    assert (
        production_oracle.capability_report().crypto_readiness.status.value == "ready"
    )
    assert isinstance(protected, EnclaveProtectedVector)
    assert shield.similarity(np.array([1.0, 0.0]), protected) == pytest.approx(1.0)
    assert (
        EnclaveProtectedVector.from_json_bytes(protected.to_json_bytes()) == protected
    )


def test_enclave_crypto_shield_rejects_short_zkp_challenge() -> None:
    class ShortChallengeProvider(_TestEnclaveProvider):
        def access_challenge(self) -> bytes:
            return b"short"

    with pytest.raises(RuntimeError, match="ZKP challenge"):
        EnclaveCryptoShield(
            ShortChallengeProvider(),
            _TestVerifier(),
            _TestProofProvider(),
        )


def test_ed25519_attestation_verifier_binds_nonce_and_measurement() -> None:
    private_key = Ed25519PrivateKey.generate()
    nonce = b"n" * 32
    now = time.time()
    claims = json.dumps(
        {
            "attestation_authority": "azure-key-vault-secure-key-release",
            "nonce_b64": base64.urlsafe_b64encode(nonce).decode(),
            "platform": "azure-amd-sev-snp-confidential-vm",
            "provider_id": "provider",
            "region": "northamerica",
            "measurement": "approved",
            "key_id": "key-1",
            "issued_at": now,
            "expires_at": now + 60,
            "ckks_security_bits": 128,
            "hardware_isolation": True,
            "zkp_access_gate": True,
            "homomorphic_similarity": True,
            "transport_public_key_b64": base64.urlsafe_b64encode(b"k" * 32).decode(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    evidence = json.dumps(
        {
            "payload_b64": base64.urlsafe_b64encode(claims).decode(),
            "signature_b64": base64.urlsafe_b64encode(
                private_key.sign(claims)
            ).decode(),
        }
    ).encode()
    verifier = Ed25519AttestationVerifier(private_key.public_key(), {"approved"})

    verified = verifier.verify(evidence, nonce)
    assert verified.measurement == "approved"
    with pytest.raises(ValueError, match="nonce"):
        verifier.verify(evidence, b"x" * 32)
    with pytest.raises(ValueError, match="measurement"):
        Ed25519AttestationVerifier(private_key.public_key(), {"different"}).verify(
            evidence, nonce
        )


def test_oracle_production_rejects_aes_gcm_shield() -> None:
    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    with pytest.raises(RuntimeError, match="EnclaveCryptoShield"):
        Oracle(environment="production", shield=shield)

    staging = Oracle(environment="staging", shield=shield)
    report = staging.capability_report().as_dict()
    assert report["crypto_readiness"]["status"] == "degraded"
    assert any("AES-GCM" in blocker for blocker in report["production_blockers"])


def test_oracle_with_aes_gcm_protects_active_vine_anchor_and_scores_decay() -> None:
    from echo_veil import WorkspaceConfig
    from echo_veil.vine import VineState

    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0), shield=shield)
    keep = oracle.sprout("keep", np.array([1.0, 0.0], dtype=np.float64))
    drop = oracle.sprout("drop", np.array([0.0, 1.0], dtype=np.float64))

    assert isinstance(keep.protected_anchor, ProtectedVector)
    assert keep.anchor.shape == (0,)
    assert isinstance(drop.protected_anchor, ProtectedVector)
    assert drop.anchor.shape == (0,)

    report = oracle.observe(np.array([1.0, 0.0], dtype=np.float64))

    assert keep.state == VineState.ACTIVE
    assert drop.state == VineState.TWILIGHT
    assert drop.vine_id in report["demoted"]


def test_protected_twilight_vine_automatically_snaps_back() -> None:
    from echo_veil import WorkspaceConfig
    from echo_veil.vine import VineState

    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    oracle = Oracle(WorkspaceConfig(capacity=2), shield=shield)
    vine = oracle.sprout("returning topic", np.array([1.0, 0.0]))
    now = time.time()

    oracle.observe(np.array([0.0, 1.0]), now=now)
    assert vine.state == VineState.TWILIGHT

    oracle.observe(np.array([1.0, 0.0]), now=now + 1)

    assert vine.state == VineState.ACTIVE
    assert vine.anchor.size == 0
    assert vine.score == pytest.approx(1.0)


def test_oracle_with_aes_gcm_indexes_and_archives_evicted_protected_vine() -> None:
    from echo_veil import WorkspaceConfig

    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    oracle = Oracle(WorkspaceConfig(capacity=2, pressure_evict_at=0.0), shield=shield)
    drop = oracle.sprout("drop", np.array([0.0, 1.0], dtype=np.float64))

    oracle.observe(np.array([1.0, 0.0], dtype=np.float64))
    drop.twilight_since -= 3600
    for _ in range(6):
        oracle.observe(np.array([1.0, 0.0], dtype=np.float64))

    assert len(oracle.index) == 1
    assert (
        oracle.search_index(np.array([0.0, 1.0], dtype=np.float64), top_k=1)[0][0]
        == drop.vine_id
    )

    archived = oracle.archive.get(drop.vine_id)
    assert archived is not None
    restored = ProtectedVector.from_json_bytes(archived)
    assert shield.similarity(
        np.array([0.0, 1.0], dtype=np.float64), restored
    ) == pytest.approx(1.0)


def test_oracle_with_aes_gcm_garden_centroid_and_drift_use_protected_vines() -> None:
    from echo_veil import WorkspaceConfig

    shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
    oracle = Oracle(WorkspaceConfig(capacity=5, pressure_evict_at=0.0), shield=shield)
    a = oracle.sprout("a", np.array([1.0, 0.0], dtype=np.float64))
    b = oracle.sprout("b", np.array([1.0, 0.0], dtype=np.float64))
    oracle.workspace.lock(a.vine_id)
    oracle.workspace.lock(b.vine_id)

    assert np.allclose(oracle.garden_centroid(), np.array([1.0, 0.0], dtype=np.float64))

    for _ in range(3):
        oracle.observe(np.array([0.0, 1.0], dtype=np.float64))

    assert oracle.is_drifting() is True
