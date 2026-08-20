from __future__ import annotations

import hashlib
import json
import shutil
import stat
import zipfile
from pathlib import Path

import pytest

from echo_veil import codex_artifact


ROOT = Path(__file__).resolve().parents[1]


def _copy_plugin(destination: Path) -> None:
    destination.mkdir(mode=0o700)
    for relative in codex_artifact.CODEX_PLUGIN_FILES:
        target = destination.joinpath(*Path(relative).parts)
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)


def _executable(path: Path, payload: bytes) -> Path:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o700)
    return path


def _wheel_fixture(tmp_path: Path) -> tuple[Path, Path]:
    environment = tmp_path / "venv"
    interpreter = _executable(environment / "bin" / "python", b"python")
    agent = _executable(
        environment / "bin" / "echo-veil-agent",
        f"#!{interpreter}\nagent-body\n".encode(),
    )
    hook = _executable(
        environment / "bin" / "echo-veil-preflight-hook",
        f"#!{interpreter}\nhook-body\n".encode(),
    )
    _executable(
        environment / "bin" / "echo-veil-shielded-run",
        f"#!{interpreter}\nrunner-body\n".encode(),
    )
    site = environment / "lib" / "python3.10" / "site-packages"
    dist_info = site / "echo_veil-0.7.0.dist-info"
    dist_info.mkdir(parents=True)
    package_files = {
        "echo_veil/__init__.py": b'__version__ = "0.7.0"\n',
        "echo_veil_origin/__init__.py": b"# origin\n",
    }
    for relative, payload in package_files.items():
        target = site.joinpath(*Path(relative).parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(payload)
    (dist_info / "METADATA").write_text(
        "Name: echo-veil\nVersion: 0.7.0\n",
        encoding="utf-8",
    )
    wheel = tmp_path / "echo_veil-0.7.0-py3-none-any.whl"
    entry_points = (
        "[console_scripts]\n"
        "echo-veil-agent = echo_veil.agent_cli:main\n"
        "echo-veil-preflight-hook = echo_veil.agent_preflight:main\n"
        "echo-veil-shielded-run = echo_veil.guarded_runner:main\n"
    ).encode()
    with zipfile.ZipFile(wheel, "w") as bundle:
        for relative, payload in package_files.items():
            bundle.writestr(relative, payload)
        bundle.writestr(
            "echo_veil-0.7.0.dist-info/entry_points.txt",
            entry_points,
        )
    wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (dist_info / "direct_url.json").write_text(
        json.dumps(
            {
                "archive_info": {},
                "url": f"{wheel.as_uri()}#sha256={wheel_digest}",
            }
        ),
        encoding="utf-8",
    )
    return agent, hook


def test_echo_console_scripts_are_verified_against_retained_wheel(
    tmp_path: Path,
) -> None:
    agent, hook = _wheel_fixture(tmp_path)

    result = codex_artifact._verify_echo_wheel(agent, hook)

    assert result["wheel_sha256"].startswith("sha256:")
    assert result["installed_source_sha256"].startswith("sha256:")
    assert result["installed_files_verified"] == 2
    assert result["version"] == "0.7.0"

    dist_info = next(
        (agent.parent.parent / "lib").glob(
            "python*/site-packages/echo_veil-*.dist-info"
        )
    )
    (dist_info / "direct_url.json").write_text(
        json.dumps({"url": ROOT.as_uri(), "dir_info": {"editable": True}}),
        encoding="utf-8",
    )
    with pytest.raises(codex_artifact.CodexArtifactError, match="PEP 610"):
        codex_artifact._verify_echo_wheel(agent, hook)


def test_echo_wheel_requires_a_consistent_sha256_binding(tmp_path: Path) -> None:
    agent, hook = _wheel_fixture(tmp_path)
    dist_info = next(
        (agent.parent.parent / "lib").glob(
            "python*/site-packages/echo_veil-*.dist-info"
        )
    )
    wheel = next(tmp_path.glob("*.whl"))
    (dist_info / "direct_url.json").write_text(
        json.dumps({"archive_info": {}, "url": wheel.as_uri()}),
        encoding="utf-8",
    )
    with pytest.raises(codex_artifact.CodexArtifactError, match="unavailable"):
        codex_artifact._verify_echo_wheel(agent, hook)

    digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (dist_info / "direct_url.json").write_text(
        json.dumps(
            {
                "archive_info": {"hash": f"sha256={digest}"},
                "url": f"{wheel.as_uri()}#sha256={'0' * 64}",
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(codex_artifact.CodexArtifactError, match="disagree"):
        codex_artifact._verify_echo_wheel(agent, hook)


def test_codex_receipt_is_path_free_and_one_byte_drift_changes_authority(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin = tmp_path / "plugin"
    _copy_plugin(plugin)
    codex = _executable(tmp_path / "bin" / "codex", b"codex-v1")
    agent = _executable(tmp_path / "bin" / "echo-veil-agent", b"agent")
    hook = _executable(tmp_path / "bin" / "echo-veil-preflight-hook", b"hook")
    monkeypatch.setattr(
        codex_artifact,
        "_verify_echo_wheel",
        lambda agent_path, hook_path: {
            "agent_console_body_sha256": "sha256:" + "a" * 64,
            "hook_console_body_sha256": "sha256:" + "b" * 64,
            "installed_files_verified": 42,
            "version": "0.7.0",
            "wheel_sha256": "sha256:" + "c" * 64,
        },
    )
    values = {
        "codex_executable": str(codex),
        "echo_agent_executable": str(agent),
        "echo_hook_executable": str(hook),
        "plugin_root": str(plugin),
        "model": "gpt-test",
        "mode": "headless",
        "configuration": {"collaboration": "disabled"},
    }

    original = codex_artifact.build_codex_artifact_bundle(**values)
    serialized = json.dumps(original.receipt)
    assert str(tmp_path) not in serialized
    assert stat.S_IMODE(codex.stat().st_mode) == 0o700
    codex_artifact.verify_codex_artifact_pin(original, original.authority_id)

    target = plugin / "hooks" / "hooks.json"
    target.write_bytes(target.read_bytes() + b"\n")
    drifted = codex_artifact.build_codex_artifact_bundle(**values)
    assert drifted.authority_id != original.authority_id
    with pytest.raises(codex_artifact.CodexArtifactError, match="binding"):
        codex_artifact.verify_codex_artifact_pin(
            drifted,
            original.authority_id,
        )


def test_codex_receipt_binds_model_configuration_and_executable(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    plugin = tmp_path / "plugin"
    _copy_plugin(plugin)
    codex = _executable(tmp_path / "codex", b"codex-v1")
    agent = _executable(tmp_path / "agent", b"agent")
    hook = _executable(tmp_path / "hook", b"hook")
    monkeypatch.setattr(
        codex_artifact,
        "_verify_echo_wheel",
        lambda agent_path, hook_path: {
            "agent_console_body_sha256": "sha256:" + "a" * 64,
            "hook_console_body_sha256": "sha256:" + "b" * 64,
            "installed_files_verified": 42,
            "version": "0.7.0",
            "wheel_sha256": "sha256:" + "c" * 64,
        },
    )
    common = {
        "codex_executable": str(codex),
        "echo_agent_executable": str(agent),
        "echo_hook_executable": str(hook),
        "plugin_root": str(plugin),
        "mode": "headless",
    }
    baseline = codex_artifact.build_codex_artifact_bundle(
        **common,
        model="gpt-a",
        configuration={"sandbox": "read-only"},
    )
    model_drift = codex_artifact.build_codex_artifact_bundle(
        **common,
        model="gpt-b",
        configuration={"sandbox": "read-only"},
    )
    config_drift = codex_artifact.build_codex_artifact_bundle(
        **common,
        model="gpt-a",
        configuration={"sandbox": "workspace-write"},
    )
    codex.write_bytes(b"codex-v2")
    executable_drift = codex_artifact.build_codex_artifact_bundle(
        **common,
        model="gpt-a",
        configuration={"sandbox": "read-only"},
    )

    assert (
        len(
            {
                baseline.authority_id,
                model_drift.authority_id,
                config_drift.authority_id,
                executable_drift.authority_id,
            }
        )
        == 4
    )
