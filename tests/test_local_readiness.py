from __future__ import annotations

from dataclasses import replace

import pytest

from echo_veil.local_readiness import (
    LOCAL_PRODUCTION_MODE,
    LOCAL_STAGING_MODE,
    REMEDIATIONS,
    LocalReadinessEvidence,
    LocalReadinessState,
    build_capabilities_v1,
    remediation_messages,
)
from echo_veil.protocol_compat import CAPABILITIES_SCHEMA, parse_capabilities_v1


def _qualified_state() -> LocalReadinessState:
    return LocalReadinessState(
        configured_mode=LOCAL_PRODUCTION_MODE,
        implementation_healthy=True,
        at_rest_encrypted=True,
        protected_semantic_state=True,
        embedding_identity_verified=True,
        profile_access_verified=True,
        reconciliation_backlog=0,
        quarantined_records=0,
        plaintext_fallback_attempts=0,
        key_migration_complete=True,
        model_available=True,
        evidence=LocalReadinessEvidence(
            artifact_verified=True,
            backup_verified=True,
            restore_verified=True,
            host_boundary_verified=True,
            key_custody="macos-secure-enclave-v1",
            rollback_detection="local-best-effort",
        ),
    )


def test_host_trusted_local_readiness_never_claims_enclave_protection() -> None:
    report = build_capabilities_v1(_qualified_state())

    assert report["schema"] == CAPABILITIES_SCHEMA
    assert report["implementation_healthy"] is True
    assert report["local_production_ready"] is True
    assert report["production_ready"] is False
    assert report["protection_tier"] == "host-trusted-local"
    assert report["at_rest_encrypted"] is True
    assert report["runtime_plaintext_exposure"] == "transient-process-memory"
    assert report["hardware_isolated"] is False
    assert report["remotely_attested"] is False
    assert report["host_compromise_protected"] is False
    assert report["remediation_codes"] == []
    assert parse_capabilities_v1(report) == report


@pytest.mark.parametrize(
    ("state", "expected_code"),
    (
        (
            replace(_qualified_state(), configured_mode=LOCAL_STAGING_MODE),
            "EV-LOCAL-MODE-NOT-CONFIGURED",
        ),
        (
            replace(_qualified_state(), implementation_healthy=False),
            "EV-IMPLEMENTATION-UNHEALTHY",
        ),
        (
            replace(_qualified_state(), at_rest_encrypted=False),
            "EV-AT-REST-UNPROTECTED",
        ),
        (
            replace(_qualified_state(), protected_semantic_state=False),
            "EV-PROTECTED-STATE-INCOMPLETE",
        ),
        (
            replace(_qualified_state(), embedding_identity_verified=False),
            "EV-EMBEDDING-IDENTITY-UNVERIFIED",
        ),
        (
            replace(_qualified_state(), profile_access_verified=False),
            "EV-PROFILE-ACCESS-UNVERIFIED",
        ),
        (
            replace(
                _qualified_state(),
                evidence=replace(
                    _qualified_state().evidence,
                    artifact_verified=False,
                ),
            ),
            "EV-ARTIFACT-UNVERIFIED",
        ),
        (
            replace(
                _qualified_state(),
                evidence=replace(
                    _qualified_state().evidence,
                    backup_verified=False,
                ),
            ),
            "EV-BACKUP-UNVERIFIED",
        ),
        (
            replace(
                _qualified_state(),
                evidence=replace(
                    _qualified_state().evidence,
                    restore_verified=False,
                ),
            ),
            "EV-RESTORE-UNVERIFIED",
        ),
        (
            replace(
                _qualified_state(),
                evidence=replace(
                    _qualified_state().evidence,
                    host_boundary_verified=False,
                ),
            ),
            "EV-HOST-BOUNDARY-UNVERIFIED",
        ),
        (
            replace(
                _qualified_state(),
                evidence=replace(
                    _qualified_state().evidence,
                    key_custody="file-v1",
                ),
            ),
            "EV-KEY-CUSTODY-UNQUALIFIED",
        ),
        (
            replace(_qualified_state(), reconciliation_backlog=1),
            "EV-RECONCILIATION-PENDING",
        ),
        (
            replace(_qualified_state(), quarantined_records=1),
            "EV-QUARANTINE-NONEMPTY",
        ),
        (
            replace(_qualified_state(), plaintext_fallback_attempts=1),
            "EV-PLAINTEXT-FALLBACK",
        ),
        (
            replace(_qualified_state(), key_migration_complete=False),
            "EV-KEY-MIGRATION-INCOMPLETE",
        ),
        (
            replace(_qualified_state(), model_available=False),
            "EV-MODEL-UNAVAILABLE",
        ),
    ),
)
def test_each_local_readiness_failure_blocks_with_a_stable_remediation(
    state: LocalReadinessState,
    expected_code: str,
) -> None:
    report = build_capabilities_v1(state)

    assert report["local_production_ready"] is False
    assert expected_code in report["remediation_codes"]
    guidance = remediation_messages(report["remediation_codes"])
    assert guidance[expected_code] == REMEDIATIONS[expected_code]


def test_enclave_production_is_a_separate_stricter_class() -> None:
    report = build_capabilities_v1(
        replace(
            _qualified_state(),
            enclave_production_ready=True,
            hardware_isolated=True,
            remotely_attested=True,
            host_compromise_protected=True,
            evidence=replace(
                _qualified_state().evidence,
                key_custody="attested-enclave-v1",
                rollback_detection="external-monotonic",
            ),
        )
    )

    assert report["local_production_ready"] is False
    assert report["production_ready"] is True
    assert report["protection_tier"] == "attested-enclave"
    assert report["runtime_plaintext_exposure"] == "attested-enclave-boundary"
    assert report["hardware_isolated"] is True
    assert report["remotely_attested"] is True
    assert report["host_compromise_protected"] is True
    assert report["remediation_codes"] == []
    assert parse_capabilities_v1(report) == report


def test_inactive_enclave_inputs_cannot_leak_into_local_claims() -> None:
    report = build_capabilities_v1(
        replace(
            _qualified_state(),
            hardware_isolated=True,
            remotely_attested=True,
            host_compromise_protected=True,
        )
    )

    assert report["local_production_ready"] is True
    assert report["production_ready"] is False
    assert report["protection_tier"] == "host-trusted-local"
    assert report["hardware_isolated"] is False
    assert report["remotely_attested"] is False
    assert report["host_compromise_protected"] is False


def test_untrusted_strings_cannot_self_assert_readiness_evidence() -> None:
    with pytest.raises(ValueError, match="key_custody"):
        LocalReadinessEvidence(key_custody="secure; true")
    with pytest.raises(ValueError, match="rollback_detection"):
        LocalReadinessEvidence(rollback_detection="strong")
    with pytest.raises(TypeError, match="artifact_verified"):
        LocalReadinessEvidence(artifact_verified=1)  # type: ignore[arg-type]
