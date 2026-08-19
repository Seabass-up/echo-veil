"""Canonical runtime data bound into native confidential-compute evidence."""

from __future__ import annotations

import base64
import json


def _identifier(value: str, label: str, maximum: int = 512) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
        or not value.isprintable()
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{label} must be a bounded identifier")
    return value


def build_attestation_runtime_data(
    *,
    nonce: bytes,
    transport_public_key: bytes,
    provider_id: str,
    measurement: str,
    key_id: str,
    cce_policy_hash: str,
    maa_policy_hash: str,
    workload_digest: str,
) -> bytes:
    """Return the exact bounded blob whose SHA-256 enters SNP report data."""

    if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 256:
        raise ValueError("attestation nonce must contain 16..256 bytes")
    if not isinstance(transport_public_key, bytes) or len(transport_public_key) != 32:
        raise ValueError("transport public key must contain 32 bytes")
    value = {
        "cce_policy_hash": _identifier(cce_policy_hash, "CCE policy hash"),
        "key_id": _identifier(key_id, "CKKS key ID"),
        "maa_policy_hash": _identifier(maa_policy_hash, "MAA policy hash"),
        "measurement": _identifier(measurement, "launch measurement"),
        "nonce_b64": base64.urlsafe_b64encode(nonce).decode("ascii"),
        "provider_id": _identifier(provider_id, "provider ID"),
        "schema": "echo-veil-native-attestation-binding-v1",
        "transport_public_key_b64": base64.urlsafe_b64encode(
            transport_public_key
        ).decode("ascii"),
        "workload_digest": _identifier(workload_digest, "workload digest"),
    }
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
