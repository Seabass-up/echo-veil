from __future__ import annotations

from dataclasses import replace
import json
from pathlib import Path
import time

import pytest

from echo_veil import agent_memory as agent_memory_module
from echo_veil import local_authority
from echo_veil.agent_memory import AgentMemory


ROOT = Path(__file__).resolve().parents[1]


def _executable(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o700)
    return path


def _artifact_receipt(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> local_authority.VerifiedInstalledArtifact:
    interpreter = _executable(tmp_path / "venv" / "bin" / "python", b"python")
    agent = _executable(
        tmp_path / "venv" / "bin" / "echo-veil-agent",
        f"#!{interpreter}\nagent-body\n".encode(),
    )
    hook = _executable(
        tmp_path / "venv" / "bin" / "echo-veil-preflight-hook",
        f"#!{interpreter}\nhook-body\n".encode(),
    )
    runner = _executable(
        tmp_path / "venv" / "bin" / "echo-veil-shielded-run",
        f"#!{interpreter}\nrunner-body\n".encode(),
    )
    monkeypatch.setattr(
        local_authority,
        "_verify_echo_wheel",
        lambda _agent, _hook: {
            "agent_console_body_sha256": "sha256:" + "a" * 64,
            "hook_console_body_sha256": "sha256:" + "b" * 64,
            "installed_files_verified": 42,
            "installed_source_sha256": "sha256:" + "c" * 64,
            "version": "0.8.0",
            "wheel_sha256": "sha256:" + "d" * 64,
        },
    )
    return local_authority.verify_echo_artifact(
        agent_executable=agent,
        hook_executable=hook,
        runner_executable=runner,
        verified_at=1_000,
    )


def _enable_v3(memory: AgentMemory) -> None:
    while (
        memory.migrate_record_envelope_v3(confirm=True, batch_size=100)["state"]
        != "verified"
    ):
        pass


def test_installed_artifact_receipt_is_path_free_and_exact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _artifact_receipt(tmp_path, monkeypatch)
    encoded = json.dumps(receipt.as_record(), sort_keys=True)
    registry = json.loads(
        (ROOT / "protocol" / "registry-v1.json").read_text(encoding="utf-8")
    )["contracts"]["artifact_installed_echo_v1"]

    assert str(tmp_path) not in encoded
    assert set(receipt.as_record()) == set(registry["required_fields"])
    assert local_authority.parse_artifact_record(receipt.as_record()) == receipt

    tampered = dict(receipt.as_record())
    tampered["wheel_sha256"] = "sha256:" + "e" * 64
    with pytest.raises(local_authority.LocalAuthorityError, match="authority"):
        local_authority.parse_artifact_record(tampered)


def test_artifact_host_and_backup_authority_evidence_is_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = _artifact_receipt(tmp_path / "artifact", monkeypatch)
    monkeypatch.setattr(
        local_authority,
        "verify_current_echo_artifact",
        lambda: receipt,
    )
    monkeypatch.setattr(
        agent_memory_module,
        "verify_current_echo_artifact",
        lambda: receipt,
    )
    state = tmp_path / "state"
    archive = tmp_path / "backup"
    now = int(time.time())

    with AgentMemory(state) as memory:
        memory.remember("authority", "Artifact and host evidence are bound.")
        _enable_v3(memory)
        recorded = memory.qualify_installed_artifact(confirm=True)
        assert recorded.authority_id == receipt.authority_id
        artifact_only = memory.doctor()["capabilities_v1"]
        assert artifact_only["artifact_verified"] is True
        assert artifact_only["host_boundary_verified"] is False

        evidence = local_authority.HostQualificationEvidence(
            host_id="codex",
            boundary="isolated-headless",
            host_artifact_authority_id="sha256:" + "f" * 64,
            healthy_preflight_v2=True,
            healthy_receipt_verified=True,
            outage_blocked=True,
            outage_provider_calls=0,
            outage_model_calls=0,
            outage_agent_starts=0,
            outage_tool_calls=0,
            competing_mutable_memory=False,
        )
        host = memory.qualify_host_boundary(
            evidence,
            confirm=True,
            lifetime_seconds=3_600,
        )
        registry = json.loads(
            (ROOT / "protocol" / "registry-v1.json").read_text(encoding="utf-8")
        )["contracts"]["host_boundary_v1"]
        assert set(host.as_record()) == set(registry["required_fields"])
        qualified = memory.doctor()["capabilities_v1"]
        assert qualified["artifact_verified"] is True
        assert qualified["host_boundary_verified"] is True
        backup = memory.backup_create(archive)
        qualified = memory.doctor()["capabilities_v1"]
        assert qualified["backup_verified"] is True
        assert backup.artifact_digest == receipt.authority_id
        assert backup.host_authority_digest == host.authority_id

    manifest = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["artifact_digest"] == receipt.authority_id
    assert manifest["host_authority_digest"] == host.authority_id
    assert str(tmp_path) not in json.dumps(manifest)

    with AgentMemory(state) as restarted:
        qualified = restarted.doctor()["capabilities_v1"]
        assert qualified["artifact_verified"] is True
        assert qualified["host_boundary_verified"] is True

    drifted = replace(receipt, authority_id="sha256:" + "0" * 64)
    monkeypatch.setattr(
        local_authority,
        "verify_current_echo_artifact",
        lambda: drifted,
    )
    with AgentMemory(state) as drifted_open:
        report = drifted_open.doctor()["capabilities_v1"]
        assert report["artifact_verified"] is False
        assert report["host_boundary_verified"] is False
        assert report["backup_verified"] is False

    assert now <= host.verified_at <= host.expires_at


def test_host_qualification_rejects_soft_or_competing_boundaries() -> None:
    baseline = local_authority.HostQualificationEvidence(
        host_id="codex",
        boundary="direct-collaboration",
        host_artifact_authority_id="sha256:" + "1" * 64,
        healthy_preflight_v2=True,
        healthy_receipt_verified=True,
        outage_blocked=True,
        outage_provider_calls=0,
        outage_model_calls=0,
        outage_agent_starts=0,
        outage_tool_calls=0,
        competing_mutable_memory=True,
    )

    with pytest.raises(local_authority.LocalAuthorityError, match="hard boundary"):
        local_authority.verify_host_qualification(
            baseline,
            echo_artifact_authority_id="sha256:" + "2" * 64,
            preflight_authority_id="sha256:" + "3" * 64,
            profile_hash="sha256:" + "4" * 64,
            scope_id="scope-" + "5" * 32,
        )


def test_host_boundary_expiry_and_profile_drift_fail_current_status() -> None:
    evidence = local_authority.HostQualificationEvidence(
        host_id="pi",
        boundary="isolated-headless",
        host_artifact_authority_id="sha256:" + "1" * 64,
        healthy_preflight_v2=True,
        healthy_receipt_verified=True,
        outage_blocked=True,
        outage_provider_calls=0,
        outage_model_calls=0,
        outage_agent_starts=0,
        outage_tool_calls=0,
        competing_mutable_memory=False,
    )
    receipt = local_authority.verify_host_qualification(
        evidence,
        echo_artifact_authority_id="sha256:" + "2" * 64,
        preflight_authority_id="sha256:" + "3" * 64,
        profile_hash="sha256:" + "4" * 64,
        scope_id="scope-" + "5" * 32,
        verified_at=1_000,
        lifetime_seconds=60,
    )
    arguments = {
        "echo_artifact_authority_id": "sha256:" + "2" * 64,
        "preflight_authority_id": "sha256:" + "3" * 64,
        "profile_hash": "sha256:" + "4" * 64,
        "scope_id": "scope-" + "5" * 32,
    }

    assert local_authority.host_boundary_record_is_current(
        receipt.as_record(),
        now=1_059,
        **arguments,
    )
    assert not local_authority.host_boundary_record_is_current(
        receipt.as_record(),
        now=1_060,
        **arguments,
    )
    assert not local_authority.host_boundary_record_is_current(
        receipt.as_record(),
        now=1_059,
        **{**arguments, "profile_hash": "sha256:" + "6" * 64},
    )
