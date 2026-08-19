from __future__ import annotations

import base64
import io
import json
import os
import time
import urllib.error
import urllib.request
from urllib.parse import urlparse

import numpy as np
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from echo_veil import (
    CloudflareEnclaveProvider,
    CloudflareGatewayError,
    EnclaveCryptoShield,
    EnclaveProtectedVector,
    VerifiedEnclave,
)
from echo_veil.cloudflare_provider import UrllibCloudflareTransport
from echo_veil.cloudflare_provider import _NoRedirectHandler


class _GatewayTransport:
    def __init__(self) -> None:
        self.requests: list[tuple[str, dict[str, str], dict[str, object], float]] = []
        self._private_key = X25519PrivateKey.generate()
        self.public_key = self._private_key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )

    def post(self, url, headers, body, timeout_seconds):
        payload = json.loads(body)
        self.requests.append((url, dict(headers), payload, timeout_seconds))
        path = urlparse(url).path
        if path == "/v1/attest":
            nonce = base64.urlsafe_b64decode(payload["nonce_b64"])
            value = {"evidence_b64": _b64(b"vendor-evidence:" + nonce)}
        else:
            ephemeral = X25519PublicKey.from_public_bytes(
                base64.urlsafe_b64decode(payload["ephemeral_public_key_b64"])
            )
            request_nonce = base64.urlsafe_b64decode(payload["nonce_b64"])
            key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=request_nonce,
                info=b"echo-veil-cloudflare-envelope-v1:" + path.encode(),
            ).derive(self._private_key.exchange(ephemeral))
            plaintext = AESGCM(key).decrypt(
                request_nonce,
                base64.urlsafe_b64decode(payload["ciphertext_b64"]),
                path.encode(),
            )
            request_value = json.loads(plaintext)
            if path == "/v1/challenge":
                assert request_value["profile"] == "echo-universal-qwen3-v1"
                assert request_value["scope"] == "local-user"
                response_value = {"challenge_b64": _b64(b"z" * 32)}
            elif path == "/v1/session":
                assert request_value["proof_b64"] == _b64(b"zk-proof")
                assert request_value["profile"] == "echo-universal-qwen3-v1"
                assert request_value["scope"] == "local-user"
                response_value = {"session": "opaque-session"}
            elif path == "/v1/vector/encrypt":
                raw = np.asarray(request_value["vector"], dtype=np.float64).tobytes()
                response_value = {"ciphertext_b64": _b64(raw)}
            elif path == "/v1/vector/similarity":
                assert request_value["intent"] == [1.0, 0.0]
                response_value = {"score": 1.0}
            else:
                raise AssertionError(path)
            response_nonce = os.urandom(12)
            response_ciphertext = AESGCM(key).encrypt(
                response_nonce,
                json.dumps(response_value).encode(),
                path.encode() + b":response",
            )
            value = {
                "nonce_b64": _b64(response_nonce),
                "ciphertext_b64": _b64(response_ciphertext),
            }
        return json.dumps(value).encode()


class _Verifier:
    def __init__(self, transport_public_key: bytes) -> None:
        self._transport_public_key = transport_public_key

    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedEnclave:
        assert evidence == b"vendor-evidence:" + nonce
        return VerifiedEnclave(
            provider_id="sev-snp-cluster",
            measurement="approved-image",
            key_id="sealed-key",
            expires_at=time.time() + 300,
            ckks_security_bits=128,
            hardware_isolation=True,
            zkp_access_gate=True,
            homomorphic_similarity=True,
            transport_public_key=self._transport_public_key,
        )


class _ProofProvider:
    def prove(self, challenge: bytes, enclave: VerifiedEnclave) -> bytes:
        assert challenge == b"z" * 32
        return b"zk-proof"


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii")


def test_cloudflare_provider_wires_access_gateway_to_enclave_shield() -> None:
    transport = _GatewayTransport()
    provider = CloudflareEnclaveProvider(
        "https://memory.example.com",
        "client-id.access",
        "client-secret",
        transport=transport,
    )
    shield = EnclaveCryptoShield(
        provider, _Verifier(transport.public_key), _ProofProvider()
    )
    protected = shield.protect(np.array([1.0, 0.0]))

    assert isinstance(protected, EnclaveProtectedVector)
    assert shield.similarity(np.array([1.0, 0.0]), protected) == 1.0
    assert [urlparse(request[0]).path for request in transport.requests] == [
        "/v1/attest",
        "/v1/challenge",
        "/v1/session",
        "/v1/vector/encrypt",
        "/v1/vector/similarity",
    ]
    for _, headers, body, timeout in transport.requests:
        assert headers["CF-Access-Client-Id"] == "client-id.access"
        assert headers["CF-Access-Client-Secret"] == "client-secret"
        assert "client-secret" not in json.dumps(body)
        assert timeout == 10.0
    sealed_bodies = [json.dumps(request[2]) for request in transport.requests[1:]]
    assert all(
        '"vector"' not in body and '"intent"' not in body for body in sealed_bodies
    )


@pytest.mark.parametrize(
    "url",
    [
        "http://memory.example.com",
        "memory.example.com",
        "https://user:pass@memory.example.com",
        "https://memory.example.com?secret=value",
        "https://memory.example.com/not-an-origin",
    ],
)
def test_cloudflare_provider_requires_clean_https_gateway_url(url: str) -> None:
    with pytest.raises(ValueError, match="HTTPS|credential-free"):
        CloudflareEnclaveProvider(url, "id", "secret")


def test_cloudflare_provider_rejects_missing_access_credentials() -> None:
    with pytest.raises(ValueError, match="Access client ID"):
        CloudflareEnclaveProvider("https://memory.example.com", "", "secret")
    with pytest.raises(ValueError, match="Access client secret"):
        CloudflareEnclaveProvider(
            "https://memory.example.com",
            "id",
            "secret\N{NO-BREAK SPACE}suffix",
        )


def test_cloudflare_provider_loads_access_credentials_from_env(monkeypatch) -> None:
    monkeypatch.setenv("CF_ACCESS_CLIENT_ID", "id")
    monkeypatch.setenv("CF_ACCESS_CLIENT_SECRET", "secret")
    provider = CloudflareEnclaveProvider.from_env("https://memory.example.com")
    assert provider is not None


def test_cloudflare_provider_bounds_timeout() -> None:
    with pytest.raises(ValueError, match="within"):
        CloudflareEnclaveProvider(
            "https://memory.example.com", "id", "secret", timeout_seconds=61
        )


def test_cloudflare_provider_bounds_enclave_protocol_inputs() -> None:
    provider = CloudflareEnclaveProvider(
        "https://memory.example.com",
        "id",
        "secret",
        transport=_GatewayTransport(),
    )

    with pytest.raises(ValueError, match="attestation nonce"):
        provider.attest(b"short")
    with pytest.raises(ValueError, match="proof"):
        provider.open_session(b"p" * 4_097)
    with pytest.raises(ValueError, match="session"):
        provider.encrypt_vector("bad\nsession", np.array([1.0]))
    with pytest.raises(ValueError, match="session"):
        provider.encrypt_vector("bad\N{NO-BREAK SPACE}session", np.array([1.0]))
    with pytest.raises(ValueError, match="safety limit"):
        provider.encrypt_vector("session", np.ones(16_385))


def test_cloudflare_provider_rejects_invalid_profile_or_scope_binding() -> None:
    with pytest.raises(ValueError, match="profile binding"):
        CloudflareEnclaveProvider(
            "https://memory.example.com",
            "id",
            "secret",
            profile="profile with spaces",
        )
    with pytest.raises(ValueError, match="scope binding"):
        CloudflareEnclaveProvider(
            "https://memory.example.com",
            "id",
            "secret",
            scope="",
        )


def test_urllib_transport_redacts_upstream_error_body(monkeypatch) -> None:
    upstream_error = urllib.error.HTTPError(
        "https://memory.example.com/v1/attest",
        502,
        "Bad Gateway",
        {},
        io.BytesIO(b"internal secret detail"),
    )

    class RejectingOpener:
        def open(self, *_args, **_kwargs):
            raise upstream_error

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: RejectingOpener(),
    )

    with pytest.raises(CloudflareGatewayError) as caught:
        UrllibCloudflareTransport().post(
            "https://memory.example.com/v1/attest",
            {"Content-Type": "application/json"},
            b"{}",
            10.0,
        )

    assert caught.value.status_code == 502
    assert "secret" not in str(caught.value)


def test_cloudflare_transport_refuses_redirects() -> None:
    assert (
        _NoRedirectHandler().redirect_request(
            None,
            None,
            302,
            "Found",
            {},
            "https://attacker.example/steal",
        )
        is None
    )
