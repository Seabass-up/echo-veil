from __future__ import annotations

from echo_veil import NullCryptoShield, Oracle
from echo_veil.capability import CapabilityStatus


class DummyCryptoShield:
    def protect(self, anchor):
        return anchor

    def similarity(self, intent, protected_anchor):
        return 1.0


def test_development_report_marks_reference_backends_and_null_crypto() -> None:
    oracle = Oracle(environment="development")
    report = oracle.capability_report()
    data = report.as_dict()

    assert data["environment"] == "development"
    assert data["overall_status"] == CapabilityStatus.DEGRADED.value
    assert data["crypto_readiness"]["status"] == CapabilityStatus.DEGRADED.value
    assert "no confidentiality" in data["crypto_readiness"]["message"].lower()
    assert data["storage_backend"]["status"] == CapabilityStatus.DEGRADED.value
    assert data["vector_index_backend"]["status"] == CapabilityStatus.DEGRADED.value
    assert data["persistence"]["status"] == CapabilityStatus.BLOCKED.value
    assert data["confidence_gating"]["status"] == CapabilityStatus.READY.value
    assert data["thread_safety"]["status"] == CapabilityStatus.DEGRADED.value
    assert data["production_blockers"]


def test_custom_structural_shield_is_degraded_until_externally_validated() -> None:
    oracle = Oracle(environment="development", shield=DummyCryptoShield())
    report = oracle.capability_report()
    data = report.as_dict()

    assert data["crypto_readiness"]["status"] == CapabilityStatus.DEGRADED.value
    assert not any("NullCryptoShield" in blocker for blocker in data["production_blockers"])
    assert any("Custom CryptoShield" in blocker for blocker in data["production_blockers"])


def test_invalid_shield_is_blocked_if_detected_in_report() -> None:
    oracle = Oracle(environment="development")
    oracle.shield = object()  # type: ignore[assignment]

    data = oracle.capability_report().as_dict()

    assert data["crypto_readiness"]["status"] == CapabilityStatus.BLOCKED.value
    assert any("does not implement CryptoShield" in blocker for blocker in data["production_blockers"])


def test_doctor_report_alias_is_serializable() -> None:
    oracle = Oracle(environment="development", shield=NullCryptoShield(silence_warning=True))
    data = oracle.doctor_report().as_dict()
    assert isinstance(data, dict)
    assert "known_limitations" in data
