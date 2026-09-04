from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

from echo_veil import agent_cli
from echo_veil import agent_memory as agent_memory_module
from echo_veil import local_authority
from echo_veil.agent_memory import AgentMemory, HashingTextEmbedder


@pytest.fixture(autouse=True)
def _ambient_profile_is_not_the_fixture(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Real harnesses export this. Operator fixtures must select their own
    # profile explicitly instead of exercising a different empty profile.
    monkeypatch.setenv("ECHO_VEIL_PROFILE", "ambient-profile")


def _profile_snapshot(root: Path) -> dict[str, tuple[bytes, int, int]]:
    return {
        path.relative_to(root).as_posix(): (
            path.read_bytes(),
            path.stat().st_mode,
            path.stat().st_mtime_ns,
        )
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _v3_profile(state: Path) -> None:
    with AgentMemory(state) as memory:
        memory.remember("operator fixture", "The operator marker is willow nine.")
        pre_migration = memory.backup_create(state / ".pre-v3-backup")
        while True:
            result = memory.migrate_record_envelope_v3(
                confirm=True,
                batch_size=100,
                verified_backup=pre_migration,
            )
            pre_migration = None
            if result["state"] == "verified":
                break


def _artifact_receipt() -> local_authority.VerifiedInstalledArtifact:
    claims = {
        "agent_console_body_sha256": "sha256:" + "1" * 64,
        "distribution": "echo-veil",
        "hook_console_body_sha256": "sha256:" + "2" * 64,
        "installed_files_verified": 42,
        "installed_source_sha256": "sha256:" + "3" * 64,
        "runner_console_body_sha256": "sha256:" + "4" * 64,
        "schema": local_authority.INSTALLED_ARTIFACT_SCHEMA,
        "version": "0.8.0",
        "wheel_sha256": "sha256:" + "5" * 64,
    }
    authority_id = (
        "sha256:"
        + hashlib.sha256(
            local_authority.INSTALLED_ARTIFACT_DOMAIN
            + json.dumps(
                claims,
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("ascii")
        ).hexdigest()
    )
    return local_authority.VerifiedInstalledArtifact(
        authority_id=authority_id,
        wheel_sha256=str(claims["wheel_sha256"]),
        installed_source_sha256=str(claims["installed_source_sha256"]),
        version="0.8.0",
        installed_files_verified=42,
        agent_console_body_sha256=str(claims["agent_console_body_sha256"]),
        hook_console_body_sha256=str(claims["hook_console_body_sha256"]),
        runner_console_body_sha256=str(claims["runner_console_body_sha256"]),
        verified_at=1_000,
    )


def test_doctor_is_observational_and_uses_offline_read_only_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    profile = state / "default"
    before = _profile_snapshot(profile)

    result = agent_cli.main(
        ["--state-dir", str(state), "--profile", "default", "doctor"]
    )

    assert result == 0
    report = json.loads(capsys.readouterr().out)
    assert report["display_name"] == "Offline Read-Only Recall"
    assert report["mode"] == "always-available-read-only"
    assert report["canonical_mode"] == "offline-read-only"
    assert report["writes_available"] is False
    assert _profile_snapshot(profile) == before


def test_guided_setup_is_path_free_and_non_mutating(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    profile = state / "default"
    before = _profile_snapshot(profile)
    hashing = HashingTextEmbedder()

    class FakeQwen:
        name = "ollama"
        model = "qwen3-embedding:latest"
        dimension = 1024
        closed = False
        identity = (
            "ollama:qwen3-embedding:latest@sha256:"
            + ("1" * 64)
            + ":dimension:1024:instruction:"
            + ("2" * 64)
        )

        def close(self) -> None:
            type(self).closed = True

    assert hashing.identity != FakeQwen.identity
    monkeypatch.setattr(agent_cli, "_build_embedder", lambda _args: FakeQwen())
    monkeypatch.setattr(
        agent_cli.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=0,
            stdout=b"FileVault is On.\n",
            stderr=b"",
        ),
    )

    result = agent_cli.main(
        [
            "--state-dir",
            str(state),
            "--profile",
            "default",
            "--embedder",
            "ollama",
            "--destination",
            str(tmp_path / "future-backup"),
            "init",
            "local-production",
        ]
    )

    assert result == 2
    output = capsys.readouterr().out
    report = json.loads(output)
    expected_filevault = "enabled" if sys.platform == "darwin" else "not-applicable"
    assert report["checks"]["filevault"] == expected_filevault
    assert report["checks"]["embedding_profile_binding"] == "mismatched"
    assert report["checks"]["backup_evidence"] == "unverified"
    assert report["checks"]["restore_evidence"] == "unverified"
    assert "EV-EMBEDDING-IDENTITY-UNVERIFIED" in report["remediation_codes"]
    assert set(report["remediation_codes"]) == set(report["remediations"])
    assert report["mutations_performed"] is False
    assert FakeQwen.closed is True
    assert str(tmp_path) not in output
    assert _profile_snapshot(profile) == before


def test_guided_setup_rejects_unconfigured_external_monotonic_authority(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    monkeypatch.setattr(
        agent_cli,
        "verify_current_echo_artifact",
        _artifact_receipt,
    )

    result = agent_cli.main(
        [
            "--state-dir",
            str(state),
            "--profile",
            "default",
            "--destination",
            str(tmp_path / "future-backup"),
            "--rollback-detection",
            "external-monotonic",
            "init",
            "local-production",
        ]
    )

    assert result == 2
    report = json.loads(capsys.readouterr().out)
    assert report["checks"]["rollback_authority"] == "unconfigured"
    assert "rollback_authority" in report["blocking_checks"]
    assert "EV-ROLLBACK-AUTHORITY-UNAVAILABLE" in report["remediation_codes"]


def test_backup_restore_operator_commands_round_trip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    archive = tmp_path / "backup"
    target = tmp_path / "target"
    _v3_profile(state)
    common = [
        "--state-dir",
        str(state),
        "--profile",
        "default",
        "--embedder",
        "hashing",
    ]

    assert (
        agent_cli.main([*common, "--destination", str(archive), "backup", "create"])
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["schema"] == "echo-veil-backup-receipt-v1"

    assert agent_cli.main([*common, "--archive", str(archive), "backup", "verify"]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["manifest_sha256"] == created["manifest_sha256"]

    assert (
        agent_cli.main([*common, "--archive", str(archive), "--dry-run", "restore"])
        == 0
    )
    dry_run = json.loads(capsys.readouterr().out)
    assert dry_run["dry_run"] is True
    assert dry_run["profile_mutated"] is False

    assert (
        agent_cli.main(
            [
                *common,
                "--archive",
                str(archive),
                "--target-state-dir",
                str(target),
                "--confirm",
                "restore",
            ]
        )
        == 0
    )
    restored = json.loads(capsys.readouterr().out)
    assert restored["manifest_sha256"] == created["manifest_sha256"]

    with AgentMemory(target, profile="restored") as memory:
        recalled = memory.recall("willow nine")
        assert recalled["results"][0]["payload"] == (
            "The operator marker is willow nine."
        )


def test_repair_migration_requires_and_consumes_a_verified_v2_backup(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    archive = tmp_path / "pre-v3-backup"
    common = [
        "--state-dir",
        str(state),
        "--profile",
        "default",
        "--embedder",
        "hashing",
    ]
    with AgentMemory(state) as memory:
        memory.remember("operator migration", "Recovery must precede activation.")

    assert agent_cli.main([*common, "--confirm", "repair", "migrate-v3"]) == 1
    blocked = json.loads(capsys.readouterr().err)
    assert "pre-migration backup" in blocked["message"]

    assert (
        agent_cli.main([*common, "--destination", str(archive), "backup", "create"])
        == 0
    )
    created = json.loads(capsys.readouterr().out)
    assert created["schema"] == "echo-veil-backup-receipt-v1"

    assert (
        agent_cli.main(
            [
                *common,
                "--archive",
                str(archive),
                "--confirm",
                "repair",
                "migrate-v3",
            ]
        )
        == 0
    )
    migrated = json.loads(capsys.readouterr().out)
    assert migrated["state"] == "verified"
    assert migrated["preflight_protocol"] == "preflight_v2"


def test_artifact_qualification_is_confirmed_path_free_and_reverified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    receipt = _artifact_receipt()
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
    common = [
        "--state-dir",
        str(state),
        "--profile",
        "default",
        "--embedder",
        "hashing",
    ]

    assert agent_cli.main([*common, "qualify", "artifact"]) == 1
    assert json.loads(capsys.readouterr().err)["error"] == "ValueError"

    assert agent_cli.main([*common, "--confirm", "qualify", "artifact"]) == 0
    output = capsys.readouterr().out
    qualified = json.loads(output)
    assert qualified["schema"] == local_authority.INSTALLED_ARTIFACT_SCHEMA
    assert qualified["authority_id"] == receipt.authority_id
    assert str(tmp_path) not in output


def test_storage_maintenance_requires_confirmation_and_is_payload_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    common = [
        "--state-dir",
        str(state),
        "--profile",
        "default",
        "--embedder",
        "hashing",
    ]

    assert agent_cli.main([*common, "maintain", "checkpoint"]) == 1
    error = json.loads(capsys.readouterr().err)
    assert error["error"] == "ValueError"

    assert agent_cli.main([*common, "--confirm", "maintain", "checkpoint"]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["schema"] == "echo-veil-storage-maintenance-v1"
    assert result["operation"] == "checkpoint"
    assert result["payload_included"] is False
    assert result["outcomes"]["payloads"]["busy"] == 0
    assert result["outcomes"]["lifecycle"]["busy"] == 0
