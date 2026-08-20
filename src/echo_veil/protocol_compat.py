"""Compatibility-only parsers for stable Echo Veil host contracts.

These helpers intentionally know nothing about encrypted record-envelope
versions.  A harness must be able to validate the same preflight response for a
v2, v3, or mixed internal profile.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from .preflight_receipt import PREFLIGHT_RECEIPT_SCHEMA

CAPABILITIES_SCHEMA = "echo-veil-capabilities-v1"

_CAPABILITY_REQUIRED_FIELDS = frozenset(
    {
        "artifact_verified",
        "at_rest_encrypted",
        "backup_verified",
        "embedding_identity_verified",
        "hardware_isolated",
        "host_boundary_verified",
        "host_compromise_protected",
        "implementation_healthy",
        "key_custody",
        "local_production_ready",
        "production_ready",
        "protection_tier",
        "remotely_attested",
        "restore_verified",
        "rollback_detection",
        "runtime_plaintext_exposure",
        "schema",
    }
)
_CAPABILITY_OPTIONAL_FIELDS = frozenset(
    {
        "generated_at_ms",
        "limitations",
        "remediation_codes",
    }
)
_CAPABILITY_BOOLEAN_FIELDS = _CAPABILITY_REQUIRED_FIELDS - {
    "key_custody",
    "protection_tier",
    "rollback_detection",
    "runtime_plaintext_exposure",
    "schema",
}
_PREFLIGHT_REQUIRED_FIELDS = frozenset(
    {
        "authority_id",
        "context",
        "embedding_model_digest",
        "evidence",
        "host",
        "lifecycle_mutated",
        "memory_authority",
        "preflight_ready",
        "profile",
        "query_source",
        "receipt",
        "schema",
        "scope",
        "semantic",
        "telemetry",
    }
)
_PREFLIGHT_OPTIONAL_FIELDS = frozenset({"broker_transport"})
_LEGACY_PREFLIGHT_FIELDS = frozenset(
    {
        "context",
        "host",
        "memory_authority",
        "preflight_ready",
        "profile",
        "query_source",
        "scope",
        "semantic",
    }
)


def _bounded_text(value: object, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise ValueError(f"{label} is invalid")
    return value


def _bounded_string_list(value: object, label: str) -> list[str]:
    if (
        not isinstance(value, list)
        or len(value) > 64
        or any(
            not isinstance(item, str) or not item or len(item) > 256 for item in value
        )
    ):
        raise ValueError(f"{label} is invalid")
    return list(value)


def _capabilities_semantically_consistent(capabilities: Mapping[str, Any]) -> bool:
    """Reject contradictory readiness claims on the diagnostic surface.

    ``capabilities_v1`` never grants turn authority, but consumers still need
    one shared interpretation of its two mutually exclusive production
    classes.  Keeping this validation here prevents a malformed report from
    being rendered as both host-trusted and enclave-protected.
    """

    local_ready = capabilities.get("local_production_ready") is True
    enclave_ready = capabilities.get("production_ready") is True
    if local_ready and enclave_ready:
        return False

    common_ready = all(
        capabilities.get(field) is True
        for field in (
            "artifact_verified",
            "at_rest_encrypted",
            "backup_verified",
            "embedding_identity_verified",
            "host_boundary_verified",
            "implementation_healthy",
            "restore_verified",
        )
    )
    remediation_codes = capabilities.get("remediation_codes")
    no_remediations = remediation_codes is None or remediation_codes == []

    if local_ready:
        return bool(
            common_ready
            and capabilities.get("protection_tier") == "host-trusted-local"
            and capabilities.get("runtime_plaintext_exposure")
            == "transient-process-memory"
            and capabilities.get("key_custody") == "macos-secure-enclave-v1"
            and capabilities.get("hardware_isolated") is False
            and capabilities.get("remotely_attested") is False
            and capabilities.get("host_compromise_protected") is False
            and no_remediations
        )
    if enclave_ready:
        key_custody = capabilities.get("key_custody")
        return bool(
            common_ready
            and capabilities.get("protection_tier") == "attested-enclave"
            and capabilities.get("runtime_plaintext_exposure")
            == "attested-enclave-boundary"
            and isinstance(key_custody, str)
            and key_custody.startswith("attested-")
            and capabilities.get("hardware_isolated") is True
            and capabilities.get("remotely_attested") is True
            and capabilities.get("host_compromise_protected") is True
            and no_remediations
        )

    return bool(
        capabilities.get("protection_tier")
        not in {"host-trusted-local", "attested-enclave"}
        and capabilities.get("hardware_isolated") is False
        and capabilities.get("remotely_attested") is False
        and capabilities.get("host_compromise_protected") is False
    )


def parse_capabilities_v1(value: object | None) -> dict[str, Any] | None:
    """Parse the optional readiness surface without granting turn authority."""

    if value is None:
        return None
    if not isinstance(value, Mapping):
        raise ValueError("capabilities_v1 response is invalid")
    capabilities = dict(value)
    fields = set(capabilities)
    if (
        not _CAPABILITY_REQUIRED_FIELDS.issubset(fields)
        or fields - _CAPABILITY_REQUIRED_FIELDS - _CAPABILITY_OPTIONAL_FIELDS
        or capabilities.get("schema") != CAPABILITIES_SCHEMA
    ):
        raise ValueError("capabilities_v1 response is invalid")
    if any(
        not isinstance(capabilities.get(field), bool)
        for field in _CAPABILITY_BOOLEAN_FIELDS
    ):
        raise ValueError("capabilities_v1 response is invalid")
    for field in (
        "key_custody",
        "protection_tier",
        "rollback_detection",
        "runtime_plaintext_exposure",
    ):
        _bounded_text(capabilities.get(field), f"capabilities_v1 {field}")
    if "generated_at_ms" in capabilities:
        generated_at_ms = capabilities["generated_at_ms"]
        if (
            isinstance(generated_at_ms, bool)
            or not isinstance(generated_at_ms, int)
            or generated_at_ms < 0
        ):
            raise ValueError("capabilities_v1 generated_at_ms is invalid")
    for field in ("limitations", "remediation_codes"):
        if field in capabilities:
            _bounded_string_list(capabilities[field], f"capabilities_v1 {field}")
    if not _capabilities_semantically_consistent(capabilities):
        raise ValueError("capabilities_v1 response is inconsistent")
    return capabilities


def parse_preflight_v2_response_shape(
    value: object,
    *,
    expected_host: str,
    expected_profile: str,
    expected_scope: str,
    expected_query_source: str,
) -> dict[str, Any]:
    """Validate the stable unsigned response shell before receipt verification."""

    if not isinstance(value, Mapping):
        raise ValueError("preflight v2 response is invalid")
    response = dict(value)
    fields = set(response)
    if (
        not _PREFLIGHT_REQUIRED_FIELDS.issubset(fields)
        or fields - _PREFLIGHT_REQUIRED_FIELDS - _PREFLIGHT_OPTIONAL_FIELDS
        or response.get("schema") != PREFLIGHT_RECEIPT_SCHEMA
        or response.get("preflight_ready") is not True
        or response.get("memory_authority") != "echo-veil"
        or response.get("host") != expected_host
        or response.get("profile") != expected_profile
        or response.get("scope") != expected_scope
        or response.get("query_source") != expected_query_source
        or response.get("semantic") is not True
        or response.get("lifecycle_mutated") is not False
    ):
        raise ValueError("preflight v2 response binding is invalid")
    if not isinstance(response.get("evidence"), Mapping):
        raise ValueError("preflight v2 evidence is invalid")
    if not isinstance(response.get("receipt"), Mapping):
        raise ValueError("preflight v2 receipt is invalid")
    if not isinstance(response.get("telemetry"), Mapping):
        raise ValueError("preflight v2 telemetry is invalid")
    context = response.get("context")
    if (
        not isinstance(context, str)
        or not context.startswith("ECHO VEIL REQUIRED MEMORY PREFLIGHT")
        or len(context) > 16_000
    ):
        raise ValueError("preflight v2 context is invalid")
    # Deliberately do not accept or inspect record-envelope/storage fields here.
    return response


def parse_legacy_preflight_response(
    value: object,
    *,
    expected_host: str,
    expected_profile: str,
    expected_scope: str,
    expected_query_source: str,
) -> dict[str, Any]:
    """Keep the installed unsigned preflight bridge explicit and bounded."""

    if not isinstance(value, Mapping):
        raise ValueError("legacy preflight response is invalid")
    response = dict(value)
    if (
        set(response) != _LEGACY_PREFLIGHT_FIELDS
        or response.get("preflight_ready") is not True
        or response.get("memory_authority") != "echo-veil"
        or response.get("host") != expected_host
        or response.get("profile") != expected_profile
        or response.get("scope") != expected_scope
        or response.get("query_source") != expected_query_source
        or response.get("semantic") is not True
    ):
        raise ValueError("legacy preflight response binding is invalid")
    context = response.get("context")
    if (
        not isinstance(context, str)
        or not context.startswith("ECHO VEIL REQUIRED MEMORY PREFLIGHT")
        or len(context) > 16_000
    ):
        raise ValueError("legacy preflight context is invalid")
    return response


__all__ = [
    "CAPABILITIES_SCHEMA",
    "parse_capabilities_v1",
    "parse_legacy_preflight_response",
    "parse_preflight_v2_response_shape",
]
