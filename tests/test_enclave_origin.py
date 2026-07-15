from __future__ import annotations

import json
import sys
import types
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from echo_veil import (
    CloudflareEnclaveProvider,
    Ed25519AttestationVerifier,
    EnclaveCryptoShield,
    VerifiedEnclave,
)
from echo_veil_origin import AttestationSigner, EnclaveService, OriginConfig
from echo_veil_origin.core import ProtocolError, origin_token_matches
from echo_veil_origin.openfhe_engine import OpenFheCkksEngine


class _TestCkks:
    key_id = "ckks-key-1"

    def encrypt_normalized(self, vector: Sequence[float]) -> bytes:
        return json.dumps(list(vector)).encode()

    def ciphertext_dimension(self, ciphertext: bytes) -> int:
        return len(json.loads(ciphertext))

    def cosine_similarity(
        self, normalized_intent: Sequence[float], ciphertext: bytes
    ) -> float:
        anchor = json.loads(ciphertext)
        return sum(a * b for a, b in zip(anchor, normalized_intent, strict=True))


class _ProofVerifier:
    def verify(self, proof: bytes, config: OriginConfig) -> bytes:
        assert config.measurement == "approved-measurement"
        if not proof.startswith(b"proof:"):
            raise ProtocolError("invalid proof")
        return proof.removeprefix(b"proof:")


class _ProofProvider:
    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes:
        assert enclave.measurement == "approved-measurement"
        return b"proof:" + challenge


class _OriginTransport:
    def __init__(self, service: EnclaveService) -> None:
        self.service = service
        self.sealed_requests: list[tuple[str, dict[str, object]]] = []

    def post(
        self,
        url: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_seconds: float,
    ) -> bytes:
        assert headers["CF-Access-Client-Id"] == "access-id"
        assert headers["CF-Access-Client-Secret"] == "access-secret"
        assert timeout_seconds == 10.0
        path = urlparse(url).path
        payload = json.loads(body)
        if path == "/v1/attest":
            response = self.service.attest(payload)
        else:
            self.sealed_requests.append((path, payload))
            response = self.service.process_envelope(path, payload)
        return json.dumps(response).encode()


def test_openfhe_engine_enables_advanced_she_before_eval_sum_keygen(
    monkeypatch, tmp_path: Path
) -> None:
    context = types.SimpleNamespace(enabled=[])

    def enable(feature: str) -> None:
        context.enabled.append(feature)

    def eval_sum_keygen(_secret_key: object) -> None:
        assert "ADVANCEDSHE" in context.enabled

    context.Enable = enable
    context.KeyGen = lambda: types.SimpleNamespace(
        publicKey=object(), secretKey=object()
    )
    context.EvalSumKeyGen = eval_sum_keygen
    context.SerializeEvalAutomorphismKey = lambda path, _kind: (
        Path(path).write_bytes(b"eval") >= 0
    )

    class Parameters:
        def SetMultiplicativeDepth(self, _value: int) -> None:
            pass

        def SetScalingModSize(self, _value: int) -> None:
            pass

        def SetBatchSize(self, _value: int) -> None:
            pass

        def SetSecurityLevel(self, _value: str) -> None:
            pass

    openfhe: Any = types.ModuleType("openfhe")
    openfhe.CCParamsCKKSRNS = Parameters
    openfhe.PKESchemeFeature = types.SimpleNamespace(
        PKE="PKE",
        KEYSWITCH="KEYSWITCH",
        LEVELEDSHE="LEVELEDSHE",
        ADVANCEDSHE="ADVANCEDSHE",
    )
    openfhe.SecurityLevel = types.SimpleNamespace(HEStd_128_classic="HEStd_128")
    openfhe.GenCryptoContext = lambda _parameters: context
    openfhe.BINARY = "binary"

    def serialize_to_file(path: str, _value: object, _kind: str) -> bool:
        Path(path).write_bytes(b"state")
        return True

    openfhe.SerializeToFile = serialize_to_file
    monkeypatch.setitem(sys.modules, "openfhe", openfhe)

    OpenFheCkksEngine("test-key", tmp_path, batch_size=16, create_keys=True)

    assert context.enabled == ["PKE", "KEYSWITCH", "LEVELEDSHE", "ADVANCEDSHE"]


def _service():
    config = OriginConfig(
        provider_id="azure-sev-snp-eastus2",
        measurement="approved-measurement",
        key_id="ckks-key-1",
    )
    transport_key = X25519PrivateKey.generate()
    signing_key = Ed25519PrivateKey.generate()
    signer = AttestationSigner(
        signing_key,
        EnclaveService.transport_public_key(transport_key),
        config,
    )
    return (
        EnclaveService(config, transport_key, signer, _ProofVerifier(), _TestCkks()),
        signing_key,
    )


def test_origin_interoperates_with_cloudflare_provider_and_shield() -> None:
    service, signing_key = _service()
    transport = _OriginTransport(service)
    provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        transport=transport,
    )
    verifier = Ed25519AttestationVerifier(
        signing_key.public_key(), {"approved-measurement"}
    )

    shield = EnclaveCryptoShield(provider, verifier, _ProofProvider())
    protected = shield.protect(np.array([3.0, 4.0]))

    assert shield.similarity(np.array([3.0, 4.0]), protected) == pytest.approx(1.0)
    assert shield.similarity(np.array([-4.0, 3.0]), protected) == pytest.approx(0.0)
    assert [path for path, _ in transport.sealed_requests] == [
        "/v1/challenge",
        "/v1/session",
        "/v1/vector/encrypt",
        "/v1/vector/similarity",
        "/v1/vector/similarity",
    ]
    assert all(
        "3.0" not in json.dumps(body) and "4.0" not in json.dumps(body)
        for _, body in transport.sealed_requests
    )


def test_origin_consumes_challenge_exactly_once() -> None:
    service, signing_key = _service()
    provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        transport=_OriginTransport(service),
    )
    nonce = b"n" * 32
    verifier = Ed25519AttestationVerifier(
        signing_key.public_key(), {"approved-measurement"}
    )
    verified = verifier.verify(provider.attest(nonce), nonce)
    provider.bind_attestation(verified)
    challenge = provider.access_challenge()
    proof = b"proof:" + challenge

    assert provider.open_session(proof)
    with pytest.raises(ProtocolError, match="consumed"):
        provider.open_session(proof)


def test_origin_rejects_replayed_envelope() -> None:
    service, signing_key = _service()
    transport = _OriginTransport(service)
    provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        transport=transport,
    )
    nonce = b"n" * 32
    verified = Ed25519AttestationVerifier(
        signing_key.public_key(), {"approved-measurement"}
    ).verify(provider.attest(nonce), nonce)
    provider.bind_attestation(verified)
    provider.access_challenge()
    path, envelope = transport.sealed_requests[-1]

    with pytest.raises(ProtocolError, match="replayed"):
        service.process_envelope(path, envelope)


def test_origin_bearer_token_comparison_is_fail_closed() -> None:
    expected = "a" * 48
    assert origin_token_matches(expected, f"Bearer {expected}")
    assert not origin_token_matches(expected, None)
    assert not origin_token_matches(expected, "Basic " + expected)
    assert not origin_token_matches(expected, "Bearer " + "b" * 48)


def test_origin_rejects_engine_key_id_mismatch() -> None:
    service, _ = _service()
    config = OriginConfig("provider", "measurement", "different-key")
    with pytest.raises(RuntimeError, match="key ID"):
        EnclaveService(
            config,
            X25519PrivateKey.generate(),
            service._attestation_signer,  # noqa: SLF001 - targeted invariant test
            _ProofVerifier(),
            _TestCkks(),
        )
