from __future__ import annotations

import numpy as np

from echo_veil import LocalOpenFheCryptoShield, NullCryptoShield, Oracle
from echo_veil.capability import CapabilityStatus


class DummyCryptoShield:
    def protect(self, anchor):
        return anchor

    def similarity(self, intent, protected_anchor):
        return 1.0


class DummyLocalCkksEngine:
    key_id = "local-key"

    def encrypt_normalized(self, vector) -> bytes:
        return np.asarray(vector, dtype=np.float64).tobytes()

    def cosine_similarity(self, normalized_intent, ciphertext) -> float:
        return 1.0

    def ciphertext_dimension(self, ciphertext) -> int:
        return len(ciphertext) // np.dtype(np.float64).itemsize


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
    assert not any(
        "NullCryptoShield" in blocker for blocker in data["production_blockers"]
    )
    assert any(
        "Custom CryptoShield" in blocker for blocker in data["production_blockers"]
    )


def test_local_private_report_is_honest_about_its_security_boundary() -> None:
    oracle = Oracle(
        environment="local-private",
        shield=LocalOpenFheCryptoShield(DummyLocalCkksEngine()),
    )

    data = oracle.capability_report().as_dict()

    assert data["crypto_readiness"]["status"] == CapabilityStatus.READY.value
    assert "remain on this device" in data["crypto_readiness"]["message"]
    assert any(
        "remote attestation" in blocker for blocker in data["production_blockers"]
    )


def test_invalid_shield_is_blocked_if_detected_in_report() -> None:
    oracle = Oracle(environment="development")
    oracle.shield = object()  # type: ignore[assignment]

    data = oracle.capability_report().as_dict()

    assert data["crypto_readiness"]["status"] == CapabilityStatus.BLOCKED.value
    assert any(
        "does not implement CryptoShield" in blocker
        for blocker in data["production_blockers"]
    )


def test_doctor_report_alias_is_serializable() -> None:
    oracle = Oracle(
        environment="development", shield=NullCryptoShield(silence_warning=True)
    )
    data = oracle.doctor_report().as_dict()
    assert isinstance(data, dict)
    assert "known_limitations" in data
