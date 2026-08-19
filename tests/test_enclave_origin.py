from __future__ import annotations

import asyncio
import base64
import json
import os
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
from echo_veil_origin import (
    AttestationSigner,
    EnclaveService,
    OriginConfig,
    VerifiedProof,
)
from echo_veil_origin.app import (
    MAX_REQUEST_BYTES,
    _read_bounded_request_body,
    _read_origin_token,
)
from echo_veil_origin.core import ProtocolError, origin_token_matches
from echo_veil_origin.openfhe_engine import OpenFheCkksEngine
from echo_veil_origin.proof_verifier import RistrettoProofVerifier

CCE_POLICY_HASH = "cce-policy-hash"
MAA_POLICY_HASH = "maa-policy-hash"
WORKLOAD_DIGEST = "sha256:workload"


class _NativeEvidenceProvider:
    def evidence(self, runtime_data: bytes) -> bytes:
        return b"native:" + runtime_data


class _NativeVerifier:
    def verify(
        self,
        evidence: bytes,
        runtime_data: bytes,
        *,
        launch_measurement: str,
        cce_policy_hash: str,
        maa_policy_hash: str,
    ) -> None:
        assert evidence == b"native:" + runtime_data
        assert launch_measurement == "approved-measurement"
        assert cce_policy_hash == CCE_POLICY_HASH
        assert maa_policy_hash == MAA_POLICY_HASH


def _client_verifier(signing_key: Ed25519PrivateKey) -> Ed25519AttestationVerifier:
    return Ed25519AttestationVerifier(
        signing_key.public_key(),
        {"approved-measurement"},
        _NativeVerifier(),
        expected_cce_policy_hash=CCE_POLICY_HASH,
        expected_maa_policy_hash=MAA_POLICY_HASH,
        expected_workload_digest=WORKLOAD_DIGEST,
    )


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
    def __init__(self, public_key: bytes = b"p" * 32) -> None:
        self.public_key = public_key

    def verify(self, proof: bytes, config: OriginConfig) -> VerifiedProof:
        assert config.measurement == "approved-measurement"
        if not proof.startswith(b"proof:"):
            raise ProtocolError("invalid proof")
        return VerifiedProof(
            challenge=proof.removeprefix(b"proof:"),
            public_key=self.public_key,
        )


class _ProofProvider:
    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes:
        assert enclave.measurement == "approved-measurement"
        return b"proof:" + challenge


class _IdentityProofVerifier:
    def verify(self, proof: bytes, config: OriginConfig) -> VerifiedProof:
        assert config.measurement == "approved-measurement"
        if not proof.startswith(b"identity-proof:") or len(proof) < 79:
            raise ProtocolError("invalid proof")
        public_key = proof[15:47]
        challenge = proof[47:]
        return VerifiedProof(challenge=challenge, public_key=public_key)


class _IdentityProofProvider:
    def __init__(self, public_key: bytes) -> None:
        self.public_key = public_key

    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes:
        assert enclave.measurement == "approved-measurement"
        return b"identity-proof:" + self.public_key + challenge


class _StreamingRequest:
    def __init__(self, chunks: list[bytes], content_length: str | None = None) -> None:
        self._chunks = chunks
        self.headers: dict[str, str] = {}
        if content_length is not None:
            self.headers["Content-Length"] = content_length

    async def stream(self):
        for chunk in self._chunks:
            yield chunk


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


def _service(proof_verifier=None):
    config = OriginConfig(
        provider_id="azure-sev-snp-eastus2",
        measurement="approved-measurement",
        key_id="ckks-key-1",
        cce_policy_hash=CCE_POLICY_HASH,
        maa_policy_hash=MAA_POLICY_HASH,
        workload_digest=WORKLOAD_DIGEST,
    )
    transport_key = X25519PrivateKey.generate()
    signing_key = Ed25519PrivateKey.generate()
    signer = AttestationSigner(
        signing_key,
        EnclaveService.transport_public_key(transport_key),
        config,
        _NativeEvidenceProvider(),
    )
    return (
        EnclaveService(
            config,
            transport_key,
            signer,
            _ProofVerifier() if proof_verifier is None else proof_verifier,
            _TestCkks(),
        ),
        signing_key,
    )


def test_origin_config_rejects_whitespace_identifiers() -> None:
    with pytest.raises(ValueError, match="provider_id"):
        OriginConfig(
            provider_id="provider\N{NO-BREAK SPACE}name",
            measurement="measurement",
            key_id="key",
            cce_policy_hash=CCE_POLICY_HASH,
            maa_policy_hash=MAA_POLICY_HASH,
            workload_digest=WORKLOAD_DIGEST,
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
    verifier = _client_verifier(signing_key)

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
    verifier = _client_verifier(signing_key)
    verified = verifier.verify(provider.attest(nonce), nonce)
    provider.bind_attestation(verified)
    challenge = provider.access_challenge()
    proof = b"proof:" + challenge

    assert provider.open_session(proof)
    with pytest.raises(ProtocolError, match="consumed"):
        provider.open_session(proof)


def test_origin_binds_challenge_to_profile_and_scope() -> None:
    service, signing_key = _service()
    provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        profile="profile-a",
        scope="scope-a",
        transport=_OriginTransport(service),
    )
    nonce = b"n" * 32
    verified = _client_verifier(signing_key).verify(provider.attest(nonce), nonce)
    provider.bind_attestation(verified)
    challenge = provider.access_challenge()
    provider._profile = "profile-b"  # noqa: SLF001 - deliberate binding attack

    with pytest.raises(ProtocolError, match="misbound"):
        provider.open_session(b"proof:" + challenge)


def test_origin_authenticates_ckks_wrapper_before_engine_use() -> None:
    service, signing_key = _service()
    transport = _OriginTransport(service)
    provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        transport=transport,
    )
    shield = EnclaveCryptoShield(
        provider,
        _client_verifier(signing_key),
        _ProofProvider(),
    )
    protected = shield.protect(np.array([3.0, 4.0]))
    wrapper = json.loads(protected.ciphertext)
    encoded = wrapper["ciphertext_b64"]
    wrapper["ciphertext_b64"] = ("A" if encoded[0] != "A" else "B") + encoded[1:]
    tampered = type(protected)(
        provider_id=protected.provider_id,
        key_id=protected.key_id,
        ciphertext=json.dumps(wrapper, sort_keys=True, separators=(",", ":")).encode(),
        shape=protected.shape,
    )

    with pytest.raises(ProtocolError, match="authentication"):
        shield.similarity(np.array([3.0, 4.0]), tampered)


@pytest.mark.parametrize("different_profile", [False, True])
def test_origin_rejects_cross_identity_or_cross_profile_ciphertext(
    different_profile: bool,
) -> None:
    service, signing_key = _service(_IdentityProofVerifier())
    transport = _OriginTransport(service)
    verifier = _client_verifier(signing_key)
    first_provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        profile="profile-a",
        scope="local-user",
        transport=transport,
    )
    first = EnclaveCryptoShield(
        first_provider,
        verifier,
        _IdentityProofProvider(b"a" * 32),
    )
    protected = first.protect(np.array([1.0, 0.0]))

    second_provider = CloudflareEnclaveProvider(
        "https://memory.algo-cli.com",
        "access-id",
        "access-secret",
        profile="profile-b" if different_profile else "profile-a",
        scope="local-user",
        transport=transport,
    )
    second = EnclaveCryptoShield(
        second_provider,
        verifier,
        _IdentityProofProvider(b"a" * 32 if different_profile else b"b" * 32),
    )

    with pytest.raises(ProtocolError, match="authentication"):
        second.similarity(np.array([1.0, 0.0]), protected)


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
    verified = _client_verifier(signing_key).verify(provider.attest(nonce), nonce)
    provider.bind_attestation(verified)
    provider.access_challenge()
    path, envelope = transport.sealed_requests[-1]

    with pytest.raises(ProtocolError, match="replayed"):
        service.process_envelope(path, envelope)


def test_origin_does_not_cache_unauthenticated_envelopes() -> None:
    service, _ = _service()
    ephemeral = X25519PrivateKey.generate().public_key().public_bytes_raw()
    invalid = {
        "ephemeral_public_key_b64": base64.urlsafe_b64encode(ephemeral).decode(),
        "nonce_b64": base64.urlsafe_b64encode(b"n" * 12).decode(),
        "ciphertext_b64": base64.urlsafe_b64encode(b"invalid-tag").decode(),
    }

    with pytest.raises(ProtocolError, match="authentication"):
        service.process_envelope("/v1/challenge", invalid)

    assert service._seen_envelopes == {}  # noqa: SLF001 - replay-cache invariant


def test_origin_rejects_unknown_protocol_fields() -> None:
    service, _ = _service()
    with pytest.raises(ProtocolError, match="attestation request"):
        service.attest(
            {
                "nonce_b64": base64.urlsafe_b64encode(b"n" * 32).decode(),
                "unexpected": True,
            }
        )


def test_origin_bearer_token_comparison_is_fail_closed() -> None:
    expected = "a" * 48
    assert origin_token_matches(expected, f"Bearer {expected}")
    assert not origin_token_matches(expected, None)
    assert not origin_token_matches(expected, "Basic " + expected)
    assert not origin_token_matches(expected, "Bearer " + "b" * 48)


def test_origin_streams_request_body_with_a_hard_memory_bound() -> None:
    request = _StreamingRequest([b'{"ok":', b"true}"], content_length="11")

    assert asyncio.run(_read_bounded_request_body(request)) == b'{"ok":true}'

    oversized = _StreamingRequest([b"x" * MAX_REQUEST_BYTES, b"y"])
    with pytest.raises(ProtocolError, match="request size"):
        asyncio.run(_read_bounded_request_body(oversized))


@pytest.mark.parametrize("content_length", ["0", "-1", "1.5", "unknown"])
def test_origin_rejects_invalid_content_length_before_streaming(
    content_length: str,
) -> None:
    request = _StreamingRequest([b"{}"], content_length=content_length)

    with pytest.raises(ProtocolError, match="request size"):
        asyncio.run(_read_bounded_request_body(request))


def test_origin_rejects_engine_key_id_mismatch() -> None:
    service, _ = _service()
    config = OriginConfig(
        "provider",
        "measurement",
        "different-key",
        CCE_POLICY_HASH,
        MAA_POLICY_HASH,
        WORKLOAD_DIGEST,
    )
    with pytest.raises(RuntimeError, match="key ID"):
        EnclaveService(
            config,
            X25519PrivateKey.generate(),
            service._attestation_signer,  # noqa: SLF001 - targeted invariant test
            _ProofVerifier(),
            _TestCkks(),
        )


def test_origin_rejects_attestation_transport_key_mismatch() -> None:
    config = OriginConfig(
        provider_id="azure-sev-snp-eastus2",
        measurement="approved-measurement",
        key_id="ckks-key-1",
        cce_policy_hash=CCE_POLICY_HASH,
        maa_policy_hash=MAA_POLICY_HASH,
        workload_digest=WORKLOAD_DIGEST,
    )
    signing_key = Ed25519PrivateKey.generate()
    signer = AttestationSigner(
        signing_key,
        b"x" * 32,
        config,
        _NativeEvidenceProvider(),
    )

    with pytest.raises(RuntimeError, match="transport key"):
        EnclaveService(
            config,
            X25519PrivateKey.generate(),
            signer,
            _ProofVerifier(),
            _TestCkks(),
        )


@pytest.mark.skipif(os.name != "posix", reason="symbolic links require POSIX")
def test_origin_token_rejects_symbolic_link(tmp_path: Path) -> None:
    target = tmp_path / "token"
    target.write_text("t" * 48, encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "token-link"
    link.symlink_to(target)

    with pytest.raises(RuntimeError, match="symbolic link"):
        _read_origin_token(str(link))


@pytest.mark.skipif(os.name != "posix", reason="symbolic links require POSIX")
def test_origin_verifier_rejects_symbolic_link_path_components(
    tmp_path: Path,
) -> None:
    real = tmp_path / "real"
    real.mkdir()
    binary = real / "echo-veil-zkp"
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    allowlist = real / "allowed.json"
    allowlist.write_text("[]", encoding="utf-8")
    allowlist.chmod(0o600)
    linked = tmp_path / "linked"
    linked.symlink_to(real, target_is_directory=True)

    with pytest.raises(RuntimeError, match="symbolic links"):
        RistrettoProofVerifier(
            linked / binary.name,
            linked / allowlist.name,
        )
