from __future__ import annotations

import base64
import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from echo_veil.agent_broker import BROKER_SCHEMA, BROKER_TELEMETRY_SCHEMA
from echo_veil.agent_preflight import (
    EVIDENCE_BUDGET_SCHEMA,
    PREFLIGHT_TELEMETRY_SCHEMA,
    RUNTIME_STATUS_SCHEMA,
    render_preflight_evidence,
)
from echo_veil.backup import BACKUP_RECEIPT_SCHEMA, BACKUP_SCHEMA
from echo_veil.codex_artifact import CODEX_ARTIFACT_SCHEMA
from echo_veil.local_authority import (
    HOST_BOUNDARY_SCHEMA,
    INSTALLED_ARTIFACT_SCHEMA,
)
from echo_veil.preflight_receipt import (
    PREFLIGHT_RECEIPT_SCHEMA,
    PreflightReceiptVerifier,
)
from echo_veil.protocol_compat import (
    CAPABILITIES_SCHEMA,
    parse_capabilities_v1,
    parse_legacy_preflight_response,
    parse_preflight_v2_response_shape,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "protocol" / "registry-v1.json"
FIXTURE_PATH = ROOT / "protocol" / "fixtures" / "compatibility-v1.json"


def _load(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def _fixture() -> dict[str, Any]:
    return _load(FIXTURE_PATH)


def _set_path(value: object, path: str, replacement: object) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        assert isinstance(current, dict)
        current = current[part]
    assert isinstance(current, dict)
    current[parts[-1]] = replacement


def _remove_path(value: object, path: str) -> None:
    parts = path.split(".")
    current = value
    for part in parts[:-1]:
        assert isinstance(current, dict)
        current = current[part]
    assert isinstance(current, dict)
    del current[parts[-1]]


def _mutated_response(case: Mapping[str, Any], fixture: Mapping[str, Any]) -> object:
    if "response" in case:
        return copy.deepcopy(case["response"])
    response = copy.deepcopy(fixture["signed_preflight"]["response"])
    set_path = case.get("set_path")
    if isinstance(set_path, Mapping):
        _set_path(response, str(set_path["path"]), set_path["value"])
    add_path = case.get("add_path")
    if isinstance(add_path, Mapping):
        _set_path(response, str(add_path["path"]), add_path["value"])
    if "signature_b64" in case:
        _set_path(response, "receipt.signature_b64", case["signature_b64"])
    return response


def _shape(value: object, fixture: Mapping[str, Any]) -> dict[str, Any]:
    bindings = fixture["signed_preflight"]["bindings"]
    return parse_preflight_v2_response_shape(
        value,
        expected_host=str(bindings["host"]),
        expected_profile=str(bindings["profile"]),
        expected_scope=str(bindings["scope"]),
        expected_query_source=str(bindings["query_source"]),
    )


def _verifier(
    fixture: Mapping[str, Any], *, now_ms: int | None = None
) -> PreflightReceiptVerifier:
    signed = fixture["signed_preflight"]
    receipt = signed["response"]["receipt"]
    public_key = base64.urlsafe_b64decode(
        str(receipt["public_key_b64"]) + "=" * (-len(receipt["public_key_b64"]) % 4)
    )
    clock_ms = int(signed["now_ms"] if now_ms is None else now_ms)
    return PreflightReceiptVerifier(
        public_key,
        expected_authority_id=str(signed["authority_id"]),
        clock=lambda: clock_ms / 1_000,
    )


def _verify_receipt(
    response: Mapping[str, Any],
    fixture: Mapping[str, Any],
    *,
    verifier: PreflightReceiptVerifier | None = None,
) -> dict[str, object]:
    bindings = fixture["signed_preflight"]["bindings"]
    active = _verifier(fixture) if verifier is None else verifier
    return active.verify_and_consume(
        response["receipt"],
        context=response["evidence"],
        query=str(bindings["query"]),
        host=str(bindings["host"]),
        profile=str(bindings["profile"]),
        scope=str(bindings["scope"]),
        session_id=str(bindings["session_id"]),
        turn_id=str(bindings["turn_id"]),
        query_source=str(bindings["query_source"]),
        embedding_model_digest=str(bindings["embedding_model_digest"]),
        model_digest=str(bindings["model_digest"]),
        tool_manifest_digest=str(bindings["tool_manifest_digest"]),
        artifact_authority_id=str(bindings["artifact_authority_id"]),
    )


def _legacy_v2_consumer(value: object, fixture: Mapping[str, Any]) -> None:
    """Snapshot the pre-v0.8 consumer boundary used in compatibility tests."""

    response = _shape(value, fixture)
    _verify_receipt(response, fixture)


def test_protocol_registry_is_complete_and_matches_runtime_identifiers() -> None:
    registry = _load(REGISTRY_PATH)
    assert registry["registry_schema"] == "echo-veil-protocol-registry-v1"
    contracts = registry["contracts"]
    assert {
        "artifact_codex_v1",
        "artifact_installed_echo_v1",
        "artifact_pi_v1",
        "backup_manifest_v1",
        "backup_receipt_v1",
        "broker_latency_v1",
        "broker_v1_request",
        "broker_v1_response",
        "capabilities_v1",
        "doctor_current",
        "evidence_budget_v1",
        "host_boundary_v1",
        "preflight_evidence_v1",
        "preflight_legacy_response",
        "preflight_receipt_v2",
        "preflight_v2_response",
        "record_envelope_v2",
        "record_envelope_v3",
        "runtime_status_v1",
        "scoped_storage_v2",
        "telemetry_v1",
    } == set(contracts)
    assert contracts["preflight_receipt_v2"]["wire_schema"] == PREFLIGHT_RECEIPT_SCHEMA
    assert contracts["preflight_v2_response"]["wire_schema"] == PREFLIGHT_RECEIPT_SCHEMA
    assert contracts["runtime_status_v1"]["wire_schema"] == RUNTIME_STATUS_SCHEMA
    assert contracts["evidence_budget_v1"]["wire_schema"] == EVIDENCE_BUDGET_SCHEMA
    assert contracts["telemetry_v1"]["wire_schema"] == PREFLIGHT_TELEMETRY_SCHEMA
    assert contracts["broker_v1_request"]["wire_schema"] == BROKER_SCHEMA
    assert contracts["broker_latency_v1"]["wire_schema"] == BROKER_TELEMETRY_SCHEMA
    assert contracts["artifact_codex_v1"]["wire_schema"] == CODEX_ARTIFACT_SCHEMA
    assert (
        contracts["artifact_installed_echo_v1"]["wire_schema"]
        == INSTALLED_ARTIFACT_SCHEMA
    )
    assert contracts["host_boundary_v1"]["wire_schema"] == HOST_BOUNDARY_SCHEMA
    assert contracts["backup_manifest_v1"]["wire_schema"] == BACKUP_SCHEMA
    assert contracts["backup_receipt_v1"]["wire_schema"] == BACKUP_RECEIPT_SCHEMA
    assert set(contracts["backup_manifest_v1"]["semantic_invariants"]) == {
        "record-envelope-version-is-two-or-three",
        "version-two-recovery-is-device-bound",
        "version-two-recovery-never-satisfies-local-readiness",
    }
    assert set(contracts["backup_receipt_v1"]["semantic_invariants"]) == {
        "wire-shape-omits-internal-record-envelope-selector",
        "only-version-three-receipts-may-enter-readiness-evidence",
    }
    assert contracts["capabilities_v1"]["wire_schema"] == CAPABILITIES_SCHEMA
    assert contracts["record_envelope_v3"]["status"] == ("dual-read-explicit-write")
    assert contracts["capabilities_v1"]["status"] == "emitted-rpc-only"
    assert set(contracts["capabilities_v1"]["semantic_invariants"]) == {
        "production-classes-mutually-exclusive",
        "host-trusted-local-has-no-enclave-claims",
        "attested-enclave-requires-complete-isolation-claims",
        "unready-reports-cannot-use-ready-tiers",
    }
    assert set(contracts["capabilities_v1"]["optional_fields"]) == {
        "generated_at_ms",
        "limitations",
        "remediation_codes",
    }
    assert set(contracts["doctor_current"]["optional_fields"]) == {
        "capabilities_v1",
        "crypto_environment",
        "in_process_operation_serialization",
        "local_production_ready",
        "mode_alias",
        "record_envelope",
        "readiness_remediation",
    }

    fixture = _fixture()
    signed_response = fixture["signed_preflight"]["response"]
    assert set(signed_response) == set(
        contracts["preflight_v2_response"]["required_fields"]
    )
    assert set(signed_response["receipt"]) == set(
        contracts["preflight_receipt_v2"]["required_fields"]
    )
    assert set(signed_response["receipt"]["claims"]) == set(
        contracts["preflight_receipt_v2"]["signed_claim_fields"]
    )
    assert set(signed_response["evidence"]) == set(
        contracts["preflight_evidence_v1"]["required_fields"]
    )
    assert set(signed_response["evidence"]["runtime_status"]) == set(
        contracts["runtime_status_v1"]["required_fields"]
    )
    assert set(signed_response["evidence"]["evidence_budget"]) == set(
        contracts["evidence_budget_v1"]["required_fields"]
    )
    assert set(signed_response["telemetry"]) == set(
        contracts["telemetry_v1"]["required_fields"]
    )
    capabilities = fixture["capabilities_cases"]["valid"]["value"]
    assert set(capabilities) == set(contracts["capabilities_v1"]["required_fields"])
    for case in fixture["legacy_preflight_cases"].values():
        assert set(case["response"]) == set(
            contracts["preflight_legacy_response"]["required_fields"]
        )


def test_runtime_and_harness_sources_do_not_introduce_preflight_v3() -> None:
    root = Path(__file__).resolve().parents[1]
    checked_roots = (
        root / "src",
        root / "integrations",
        root / "protocol",
        root / "scripts",
        root / "hooks",
        root / "skills",
    )
    ignored_parts = {".build", "__pycache__", "node_modules"}
    negative_fixture = root / "protocol/fixtures/compatibility-v1.json"
    checked_suffixes = {".js", ".json", ".mjs", ".py", ".sh", ".ts", ".yaml", ".yml"}
    forbidden = (b"preflight_v3", b"echo-veil-preflight-v3")
    violations: list[str] = []
    for checked_root in checked_roots:
        for path in checked_root.rglob("*"):
            if (
                not path.is_file()
                or path.suffix not in checked_suffixes
                or ignored_parts.intersection(path.parts)
                or path == negative_fixture
            ):
                continue
            encoded = path.read_bytes()
            if any(value in encoded for value in forbidden):
                violations.append(path.relative_to(root).as_posix())

    assert violations == []


def test_every_legacy_harness_fixture_keeps_the_pre_v2_bridge() -> None:
    cases = _fixture()["legacy_preflight_cases"]
    assert set(cases) == {
        "aip",
        "claude-code",
        "codex",
        "droid",
        "goose",
        "grok-build",
        "hermes",
        "openclaw",
        "opencode",
    }
    for host, case in cases.items():
        response = parse_legacy_preflight_response(
            case["response"],
            expected_host=host,
            expected_profile="echo-universal-qwen3-v1",
            expected_scope="local-user",
            expected_query_source="current_user_prompt",
        )
        assert response["context"].startswith("ECHO VEIL REQUIRED MEMORY PREFLIGHT")
        assert "record_envelope" not in response


@pytest.mark.parametrize(
    "case_name",
    (
        "normal_semantic",
        "ambiguous_ranking",
        "competing_memory",
        "contextual_logic",
        "gated_memory",
        "payload_omission",
        "poisoned_untrusted_memory",
    ),
)
def test_shared_evidence_fixtures_round_trip(case_name: str) -> None:
    case = _fixture()["evidence_cases"][case_name]
    evidence = case["evidence"]
    expected = case["expected"]
    assert render_preflight_evidence(evidence) == case["context"]
    recall = evidence["recall"]
    assert len(recall["results"]) >= expected["minimum_results"]
    if expected.get("ranking_ambiguous"):
        assert recall["ranking_ambiguous"] is True
    if expected.get("competing_memory_detected"):
        assert recall["competing_memory_detected"] is True
    if expected.get("contextual_logic_required"):
        assert evidence["contextual_logic"] is not None
        assert evidence["runtime_status"]["contextual_logic_checked"] is True
    if "gated_count" in expected:
        assert recall["gated_count"] == expected["gated_count"]
        assert recall["results"][0]["payload"] is None
    if "minimum_payloads_omitted" in expected:
        assert (
            evidence["evidence_budget"]["payloads_omitted"]
            >= expected["minimum_payloads_omitted"]
        )
    if expected.get("escaped_untrusted_text"):
        assert "<script>" not in case["context"]
        assert "\\u003cscript\\u003e" in case["context"]
        assert evidence["trust"] == "untrusted_memory_evidence"


def test_shared_signed_preflight_fixture_is_valid_and_exact() -> None:
    fixture = _fixture()
    response = _shape(fixture["signed_preflight"]["response"], fixture)
    claims = _verify_receipt(response, fixture)
    assert claims["schema"] == PREFLIGHT_RECEIPT_SCHEMA
    assert "record_envelope" not in response
    assert "record_envelope" not in claims


@pytest.mark.parametrize(
    "case_name",
    (
        "downgraded_signed_schema",
        "expired_receipt",
        "extra_signed_claim",
        "invalid_signature",
        "malformed_response",
        "unknown_response_schema",
        "unknown_signed_schema",
        "wrong_host",
        "wrong_profile",
        "wrong_scope",
    ),
)
def test_shared_negative_preflight_cases_fail_closed(case_name: str) -> None:
    fixture = _fixture()
    case = fixture["preflight_cases"][case_name]
    response = _mutated_response(case, fixture)
    with pytest.raises((TypeError, ValueError)):
        shaped = _shape(response, fixture)
        verifier = _verifier(fixture, now_ms=case.get("now_ms"))
        _verify_receipt(shaped, fixture, verifier=verifier)


def test_shared_replay_case_rejects_second_consumption() -> None:
    fixture = _fixture()
    response = _shape(fixture["signed_preflight"]["response"], fixture)
    verifier = _verifier(fixture)
    _verify_receipt(response, fixture, verifier=verifier)
    with pytest.raises(ValueError, match="already consumed"):
        _verify_receipt(response, fixture, verifier=verifier)


def test_shared_outage_and_oversized_prompt_cases_block_before_execution() -> None:
    cases = _fixture()["preflight_cases"]
    assert cases["forced_outage"] == {
        "expected": "block-before-provider",
        "response": None,
    }
    oversized = cases["oversized_prompt"]["query_construction"]
    query = str(oversized["character"]) * int(oversized["length"])
    assert len(query) == 20_001
    assert cases["oversized_prompt"]["expected"] == "block-before-rpc"


def test_capabilities_v1_is_optional_and_uses_only_documented_additions() -> None:
    cases = _fixture()["capabilities_cases"]
    assert parse_capabilities_v1(cases["absent"]["value"]) is None
    assert (
        parse_capabilities_v1(cases["valid"]["value"])["schema"] == CAPABILITIES_SCHEMA
    )
    extended = parse_capabilities_v1(cases["valid_documented_additions"]["value"])
    assert extended is not None
    assert extended["remediation_codes"] == ["EV-BACKUP-UNVERIFIED"]
    local_ready = parse_capabilities_v1(cases["host_trusted_local_ready"]["value"])
    assert local_ready is not None
    assert local_ready["local_production_ready"] is True
    assert local_ready["production_ready"] is False
    enclave_ready = parse_capabilities_v1(cases["attested_enclave_ready"]["value"])
    assert enclave_ready is not None
    assert enclave_ready["local_production_ready"] is False
    assert enclave_ready["production_ready"] is True
    for case_name in (
        "missing_required",
        "unknown_schema",
        "both_production_classes_ready",
        "local_ready_with_enclave_claims",
        "enclave_ready_without_isolation",
        "unready_with_ready_tier",
    ):
        case = cases[case_name]
        value = copy.deepcopy(case["value"])
        if "remove_path" in case:
            _remove_path({"value": value}, str(case["remove_path"]))
        if "set_path" in case:
            mutation = case["set_path"]
            _set_path({"value": value}, str(mutation["path"]), mutation["value"])
        with pytest.raises(ValueError):
            parse_capabilities_v1(value)


def test_cross_version_matrix_keeps_record_envelopes_out_of_harness_contracts() -> None:
    fixture = _fixture()
    cases = fixture["preflight_cases"]
    for row in fixture["compatibility_matrix"]:
        if row["expected"] == "accept":
            response = fixture["signed_preflight"]["response"]
            if row["consumer"] == "existing-v2":
                _legacy_v2_consumer(response, fixture)
            else:
                shaped = _shape(response, fixture)
                _verify_receipt(shaped, fixture)
            assert row["record_envelope"] in {"v2", "v3", "mixed-v2-v3"}
            continue
        case = cases[row["response_case"]]
        with pytest.raises((TypeError, ValueError)):
            response = _mutated_response(case, fixture)
            shaped = _shape(response, fixture)
            _verify_receipt(shaped, fixture)
