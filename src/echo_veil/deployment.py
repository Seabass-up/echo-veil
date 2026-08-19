"""Fail-closed production construction from deployment-injected values."""

from __future__ import annotations

import base64
import hmac
import os

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ._json import strict_json_loads
from .azure_attestation import AzureMaaJwtVerifier
from .cloudflare_provider import CloudflareEnclaveProvider, CloudflareTransport
from .crypto_shield import Ed25519AttestationVerifier, EnclaveCryptoShield
from .zkp import RistrettoSchnorrProofProvider

DEFAULT_GATEWAY_URL = "https://memory.algo-cli.com"


def _required_env(name: str) -> str:
    value = os.environ.get(name, "")
    if not value or value != value.strip():
        raise ValueError(f"{name} is required")
    return value


def _attestation_public_key() -> Ed25519PublicKey:
    encoded = _required_env("ECHO_VEIL_ATTESTATION_PUBLIC_KEY")
    try:
        raw = base64.b64decode(encoded.encode("ascii"), altchars=b"-_", validate=True)
    except Exception as exc:
        raise ValueError("ECHO_VEIL_ATTESTATION_PUBLIC_KEY is invalid base64") from exc
    if len(raw) != 32 or not hmac.compare_digest(
        base64.urlsafe_b64encode(raw), encoded.encode("ascii")
    ):
        raise ValueError("ECHO_VEIL_ATTESTATION_PUBLIC_KEY must decode to 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def _allowed_measurements() -> set[str]:
    raw = _required_env("ECHO_VEIL_ALLOWED_MEASUREMENTS")
    try:
        values = strict_json_loads(raw)
    except Exception as exc:
        raise ValueError("ECHO_VEIL_ALLOWED_MEASUREMENTS must be a JSON array") from exc
    if (
        not isinstance(values, list)
        or not 0 < len(values) <= 16
        or not all(
            isinstance(value, str)
            and value
            and value == value.strip()
            and len(value) <= 512
            and "SET_" not in value
            and value.isprintable()
            and not any(character.isspace() for character in value)
            for value in values
        )
        or len(set(values)) != len(values)
    ):
        raise ValueError(
            "ECHO_VEIL_ALLOWED_MEASUREMENTS must contain 1..16 real measurements"
        )
    return set(values)


def build_production_enclave_shield_from_env(
    *, transport: CloudflareTransport | None = None
) -> EnclaveCryptoShield:
    """Attest the configured Algo-cli origin and open a proof-gated session.

    Construction performs live network attestation and therefore fails before
    returning if Access, evidence, measurement, CKKS capabilities, transport-key
    binding, the Ristretto proof, or session issuance is invalid.
    """
    gateway_url = os.environ.get("ECHO_VEIL_GATEWAY_URL", DEFAULT_GATEWAY_URL)
    if not gateway_url or gateway_url != gateway_url.strip():
        raise ValueError("ECHO_VEIL_GATEWAY_URL must not be empty")
    provider = CloudflareEnclaveProvider(
        gateway_url,
        _required_env("CF_ACCESS_CLIENT_ID"),
        _required_env("CF_ACCESS_CLIENT_SECRET"),
        profile=_required_env("ECHO_VEIL_PROFILE"),
        scope=_required_env("ECHO_VEIL_SCOPE"),
        transport=transport,
    )
    verifier = Ed25519AttestationVerifier(
        _attestation_public_key(),
        _allowed_measurements(),
        AzureMaaJwtVerifier.from_jwks_file(
            _required_env("ECHO_VEIL_MAA_ISSUER"),
            _required_env("ECHO_VEIL_MAA_JWKS_FILE"),
        ),
        expected_cce_policy_hash=_required_env("ECHO_VEIL_CCE_POLICY_HASH"),
        expected_maa_policy_hash=_required_env("ECHO_VEIL_MAA_POLICY_HASH"),
        expected_workload_digest=_required_env("ECHO_VEIL_WORKLOAD_DIGEST"),
    )
    proof_provider = RistrettoSchnorrProofProvider.from_env()
    raw_security = os.environ.get("ECHO_VEIL_MINIMUM_CKKS_SECURITY_BITS", "128")
    if raw_security != raw_security.strip() or not raw_security.isascii():
        raise ValueError("ECHO_VEIL_MINIMUM_CKKS_SECURITY_BITS must be an integer")
    try:
        minimum_security_bits = int(raw_security)
    except ValueError as exc:
        raise ValueError(
            "ECHO_VEIL_MINIMUM_CKKS_SECURITY_BITS must be an integer"
        ) from exc
    return EnclaveCryptoShield(
        provider,
        verifier,
        proof_provider,
        minimum_security_bits=minimum_security_bits,
    )
