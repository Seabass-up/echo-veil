from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from echo_veil import agent_cli
from echo_veil.agent_memory import AgentMemory, HashingTextEmbedder


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
        while (
            memory.migrate_record_envelope_v3(confirm=True, batch_size=100)["state"]
            != "verified"
        ):
            pass


def test_doctor_is_observational_and_uses_offline_read_only_name(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    profile = state / "default"
    before = _profile_snapshot(profile)

    result = agent_cli.main(["--state-dir", str(state), "doctor"])

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
        identity = (
            "ollama:qwen3-embedding:latest@sha256:"
            + ("1" * 64)
            + ":dimension:1024:instruction:"
            + ("2" * 64)
        )

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
    assert report["checks"]["filevault"] == "enabled"
    assert report["checks"]["embedding_profile_binding"] == "mismatched"
    assert report["mutations_performed"] is False
    assert str(tmp_path) not in output
    assert _profile_snapshot(profile) == before


def test_backup_restore_operator_commands_round_trip(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    archive = tmp_path / "backup"
    target = tmp_path / "target"
    _v3_profile(state)
    common = ["--state-dir", str(state), "--embedder", "hashing"]

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


def test_storage_maintenance_requires_confirmation_and_is_payload_free(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state = tmp_path / "state"
    _v3_profile(state)
    common = ["--state-dir", str(state), "--embedder", "hashing"]

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
