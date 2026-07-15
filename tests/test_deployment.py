from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from echo_veil.deployment import _allowed_measurements, _attestation_public_key


def test_deployment_loads_public_key_and_measurement_allowlist(monkeypatch) -> None:
    public_key = Ed25519PrivateKey.generate().public_key()
    from cryptography.hazmat.primitives import serialization

    encoded = base64.urlsafe_b64encode(
        public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
    ).decode()
    monkeypatch.setenv("ECHO_VEIL_ATTESTATION_PUBLIC_KEY", encoded)
    monkeypatch.setenv(
        "ECHO_VEIL_ALLOWED_MEASUREMENTS",
        json.dumps(["sha256:approved-enclave-image"]),
    )

    assert _attestation_public_key() is not None
    assert _allowed_measurements() == {"sha256:approved-enclave-image"}


@pytest.mark.parametrize(
    "value",
    ["", "not-json", "[]", '["SET_AFTER_DEPLOYMENT"]', '[""]'],
)
def test_deployment_rejects_missing_or_placeholder_measurements(
    monkeypatch, value: str
) -> None:
    monkeypatch.setenv("ECHO_VEIL_ALLOWED_MEASUREMENTS", value)
    with pytest.raises(ValueError, match="MEASUREMENTS"):
        _allowed_measurements()


def test_deployment_requires_real_access_credentials(monkeypatch) -> None:
    from echo_veil import build_production_enclave_shield_from_env

    monkeypatch.delenv("CF_ACCESS_CLIENT_ID", raising=False)
    monkeypatch.delenv("CF_ACCESS_CLIENT_SECRET", raising=False)
    with pytest.raises(ValueError, match="CF_ACCESS_CLIENT_ID"):
        build_production_enclave_shield_from_env()
