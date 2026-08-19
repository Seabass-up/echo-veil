from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import urllib.request

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from echo_veil import AzureMaaJwtVerifier
from echo_veil_origin.native_attestation import AzureMaaEvidenceProvider

NOW = 1_800_000_000.0
ISSUER = "https://echo-veil.eus2.attest.azure.net"
KID = "maa-key-1"
CCE_POLICY_HASH = "a" * 64
MAA_POLICY_HASH = "approved-maa-policy"
MEASUREMENT = "b" * 96


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwks(private_key: rsa.RSAPrivateKey) -> dict[str, object]:
    numbers = private_key.public_key().public_numbers()
    return {
        "keys": [
            {
                "alg": "RS256",
                "e": _b64url(
                    numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
                ),
                "kid": KID,
                "kty": "RSA",
                "n": _b64url(
                    numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
                ),
                "use": "sig",
            }
        ]
    }


def _claims(runtime_data: bytes, **overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "exp": NOW + 120,
        "iat": NOW,
        "iss": ISSUER,
        "jti": "fresh-token-id",
        "nbf": NOW,
        "x-ms-attestation-type": "sevsnpvm",
        "x-ms-compliance-status": "azure-compliant-uvm",
        "x-ms-policy-hash": MAA_POLICY_HASH,
        "x-ms-sevsnpvm-hostdata": CCE_POLICY_HASH,
        "x-ms-sevsnpvm-is-debuggable": False,
        "x-ms-sevsnpvm-launchmeasurement": MEASUREMENT,
        "x-ms-sevsnpvm-migration-allowed": False,
        "x-ms-sevsnpvm-reportdata": hashlib.sha256(runtime_data).hexdigest() + "0" * 64,
        "x-ms-sevsnpvm-vmpl": 0,
    }
    value.update(overrides)
    return value


def _token(private_key: rsa.RSAPrivateKey, claims: dict[str, object]) -> bytes:
    header = _b64url(
        json.dumps(
            {"alg": "RS256", "kid": KID, "typ": "JWT"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    )
    payload = _b64url(
        json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
    )
    signing_input = f"{header}.{payload}".encode("ascii")
    signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}".encode("ascii")


def _verifier(tmp_path: Path, private_key: rsa.RSAPrivateKey) -> AzureMaaJwtVerifier:
    path = tmp_path / "maa-jwks.json"
    path.write_text(json.dumps(_jwks(private_key)), encoding="utf-8")
    path.chmod(0o600)
    return AzureMaaJwtVerifier.from_jwks_file(
        ISSUER,
        path,
        clock=lambda: NOW,
    )


def test_azure_maa_verifier_binds_fresh_hardware_policy_and_runtime_data(
    tmp_path: Path,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    runtime_data = b"nonce+transport+workload binding"
    verifier = _verifier(tmp_path, private_key)

    claims = verifier.verify(
        _token(private_key, _claims(runtime_data)),
        runtime_data,
        launch_measurement=MEASUREMENT,
        cce_policy_hash=CCE_POLICY_HASH,
        maa_policy_hash=MAA_POLICY_HASH,
    )

    assert claims["x-ms-attestation-type"] == "sevsnpvm"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"x-ms-sevsnpvm-hostdata": "c" * 64}, "CCE policy"),
        ({"x-ms-policy-hash": "other"}, "MAA policy"),
        ({"x-ms-sevsnpvm-launchmeasurement": "d" * 96}, "measurement"),
        ({"x-ms-sevsnpvm-is-debuggable": True}, "hardware claims"),
        ({"exp": NOW - 1}, "fresh"),
    ],
)
def test_azure_maa_verifier_rejects_invalid_native_claims(
    tmp_path: Path,
    override: dict[str, object],
    message: str,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    runtime_data = b"runtime binding"
    verifier = _verifier(tmp_path, private_key)

    with pytest.raises(ValueError, match=message):
        verifier.verify(
            _token(private_key, _claims(runtime_data, **override)),
            runtime_data,
            launch_measurement=MEASUREMENT,
            cce_policy_hash=CCE_POLICY_HASH,
            maa_policy_hash=MAA_POLICY_HASH,
        )


def test_azure_maa_verifier_rejects_runtime_binding_or_signature_tampering(
    tmp_path: Path,
) -> None:
    private_key = rsa.generate_private_key(public_exponent=65_537, key_size=2_048)
    runtime_data = b"runtime binding"
    verifier = _verifier(tmp_path, private_key)
    token = _token(private_key, _claims(runtime_data))

    with pytest.raises(ValueError, match="runtime data"):
        verifier.verify(
            token,
            b"different runtime binding",
            launch_measurement=MEASUREMENT,
            cce_policy_hash=CCE_POLICY_HASH,
            maa_policy_hash=MAA_POLICY_HASH,
        )
    tampered = token[:-1] + (b"A" if token[-1:] != b"A" else b"B")
    with pytest.raises(ValueError, match="signature or format"):
        verifier.verify(
            tampered,
            runtime_data,
            launch_measurement=MEASUREMENT,
            cce_policy_hash=CCE_POLICY_HASH,
            maa_policy_hash=MAA_POLICY_HASH,
        )


def test_origin_fetches_each_native_token_from_loopback_sidecar(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    token = b"header.payload.signature"
    raw_response = json.dumps({"token": token.decode()}).encode()
    requests: list[urllib.request.Request] = []

    class Response:
        headers = {"Content-Length": str(len(raw_response))}

        def __enter__(self):
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, _maximum: int) -> bytes:
            return raw_response

    class Opener:
        def open(self, request: urllib.request.Request, *, timeout: float):
            assert timeout == 10.0
            requests.append(request)
            return Response()

    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *_handlers: Opener(),
    )
    provider = AzureMaaEvidenceProvider(
        "http://127.0.0.1:8080/attest/maa",
        ISSUER,
    )

    assert provider.evidence(b"first binding") == token
    assert provider.evidence(b"second binding") == token
    assert len(requests) == 2
    first = json.loads(requests[0].data)
    second = json.loads(requests[1].data)
    assert base64.b64decode(first["runtime_data"]) == b"first binding"
    assert base64.b64decode(second["runtime_data"]) == b"second binding"
