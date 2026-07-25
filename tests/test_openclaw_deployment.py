from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import zipfile
from pathlib import Path
from typing import Any

import pytest

from scripts.verify_openclaw_deployment import (
    DeploymentError,
    REQUIRED_HOOKS,
    REQUIRED_TOOLS,
    evaluate_doctor,
    evaluate_openclaw_state,
    load_lock,
    verify_plugin_artifact,
    verify_python_artifact,
)


ROOT = Path(__file__).resolve().parents[1]


def _lock() -> dict[str, Any]:
    return load_lock(ROOT / "integrations/openclaw/deployment-lock.json")


def _runtime_fixture(lock: dict[str, Any]) -> dict[str, Any]:
    return {
        "status": {
            "service": {"runtime": {"status": "running"}},
            "rpc": {
                "ok": True,
                "server": {"version": lock["openclaw_version"]},
            },
            "gateway": {"bindHost": "127.0.0.1"},
            "pluginVersionDrift": {"drifts": []},
        },
        "inspection": {
            "plugin": {
                "id": "echo-veil",
                "version": lock["plugin"]["version"],
                "status": "loaded",
                "activated": True,
                "memorySlotSelected": True,
                "toolNames": sorted(REQUIRED_TOOLS),
            },
            "typedHooks": [
                {"name": name, "priority": 1_000} for name in sorted(REQUIRED_HOOKS)
            ],
            "diagnostics": [],
        },
        "audit": {
            "summary": {"critical": 0, "warn": 0, "info": 2},
            "secretDiagnostics": [],
        },
        "config": {
            "echo_entry": {
                "enabled": True,
                "hooks": {
                    "allowConversationAccess": True,
                    "allowPromptInjection": True,
                },
                "config": {
                    "executable": "/opt/echo/echo-veil-agent",
                    "profile": lock["profile"]["id"],
                },
            },
            "memory_slot": "echo-veil",
            "session_memory_enabled": False,
            "plugin_load_paths": [],
            "plugin_allowlist": ["echo-veil"],
            "agents": [
                {
                    "id": "main",
                    "tools": {"alsoAllow": sorted(REQUIRED_TOOLS)},
                }
            ],
            "models": {"provider/model": {"agentRuntime": {"id": "openclaw"}}},
            "gateway_bind": "loopback",
            "gateway_auth_mode": "token",
            "allow_insecure_control_ui": False,
            "trusted_proxies": ["127.0.0.1"],
            "tailscale_mode": "serve",
        },
    }


def _doctor_fixture(lock: dict[str, Any]) -> dict[str, Any]:
    return {
        "profile": lock["profile"]["id"],
        "production_ready": False,
        "failed_decryptions": 0,
        "plaintext_fallback_attempts": 0,
        "reconciliation_backlog": 0,
        "store_permissions": "valid",
        "key_owner_only": True,
        "readiness": {
            "enabled": True,
            "healthy": True,
            "installed": True,
            "write_wired": True,
            "retrieval_wired": True,
            "persistence_wired": True,
            "restart_restored": True,
            "layer_contract_wired": True,
            "live_refresh_wired": True,
            "competing_memory_wired": True,
            "context_trace_wired": True,
        },
        "memory_layers": {
            "all_records_shielded": True,
            "unprotected_record_count": 0,
            "unpaired_lifecycle_record_count": 0,
        },
        "retrieval": {"unindexed_payload_count": 0},
        "embedding": {
            "backend": lock["profile"]["embedding_backend"],
            "model": lock["profile"]["embedding_model"],
            "dimension": lock["profile"]["embedding_dimension"],
            "semantic": True,
        },
    }


def test_deployment_lock_and_healthy_local_staging_contract() -> None:
    lock = _lock()
    fixture = _runtime_fixture(lock)

    assert lock["source_date_epoch"] == 1_784_937_600
    assert (
        evaluate_openclaw_state(
            lock=lock,
            status=fixture["status"],
            inspection=fixture["inspection"],
            audit=fixture["audit"],
            config=fixture["config"],
            memory_core_absent=True,
            agent_id="main",
        )
        == []
    )
    assert (
        evaluate_doctor(
            _doctor_fixture(lock),
            lock,
            require_production_ready=False,
        )
        == []
    )
    assert evaluate_doctor(
        _doctor_fixture(lock),
        lock,
        require_production_ready=True,
    ) == ["production_readiness_blocked"]


@pytest.mark.parametrize(
    ("mutation", "failure"),
    [
        (
            lambda value: value["inspection"]["plugin"]["toolNames"].remove(
                "echo_veil_context"
            ),
            "nine_tool_contract_missing",
        ),
        (
            lambda value: value["config"].update(
                {"plugin_load_paths": ["/mutable/checkout"]}
            ),
            "mutable_plugin_load_path_configured",
        ),
        (
            lambda value: value["config"]["echo_entry"]["config"].update(
                {"projectPath": "/mutable/checkout"}
            ),
            "mutable_project_path_configured",
        ),
        (
            lambda value: value["config"].update({"session_memory_enabled": True}),
            "native_session_memory_enabled",
        ),
        (
            lambda value: value["config"].update({"allow_insecure_control_ui": True}),
            "insecure_control_ui_enabled",
        ),
        (
            lambda value: value["config"]["agents"][0]["tools"].update(
                {"alsoAllow": ["echo_veil_recall"]}
            ),
            "agent_tool_allowlist_incomplete",
        ),
    ],
)
def test_deployment_gate_rejects_runtime_and_config_drift(
    mutation: Any,
    failure: str,
) -> None:
    lock = _lock()
    fixture = _runtime_fixture(lock)
    mutation(fixture)

    failures = evaluate_openclaw_state(
        lock=lock,
        status=fixture["status"],
        inspection=fixture["inspection"],
        audit=fixture["audit"],
        config=fixture["config"],
        memory_core_absent=True,
        agent_id="main",
    )

    assert failure in failures


def _write_plugin_archive(
    tmp_path: Path,
    entrypoint: bytes,
) -> tuple[Path, Path, Path]:
    root = tmp_path / "extension"
    source = root / "dist" / "index.js"
    source.parent.mkdir(parents=True)
    source.write_bytes(entrypoint)
    archive = tmp_path / "echo-veil.tgz"
    with tarfile.open(archive, "w:gz") as bundle:
        member = tarfile.TarInfo("package/dist/index.js")
        member.size = len(entrypoint)
        bundle.addfile(member, io.BytesIO(entrypoint))
    os.chmod(archive, 0o600)
    return root, source, archive


def test_plugin_artifact_must_match_archive_and_installed_entrypoint(
    tmp_path: Path,
) -> None:
    entrypoint = b"export default function echoVeil() {};\n"
    root, source, archive = _write_plugin_archive(tmp_path, entrypoint)
    lock = {
        "plugin": {
            "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
            "entrypoint_sha256": hashlib.sha256(entrypoint).hexdigest(),
        }
    }
    inspection = {
        "plugin": {
            "rootDir": str(root),
            "source": str(source),
            "version": "0.7.0",
        },
        "install": {"source": "archive", "sourcePath": str(archive)},
    }

    assert verify_plugin_artifact(inspection, lock)["artifact_bound"] is True
    source.write_text("modified\n", encoding="utf-8")
    with pytest.raises(DeploymentError, match="entrypoint hash"):
        verify_plugin_artifact(inspection, lock)


def _write_python_install(
    tmp_path: Path,
) -> tuple[Path, dict[str, Any]]:
    venv = tmp_path / "venv"
    site = venv / "lib" / "python3.14" / "site-packages"
    package = site / "echo_veil"
    dist_info = site / "echo_veil-0.7.0.dist-info"
    package.mkdir(parents=True)
    dist_info.mkdir()
    source = b"VALUE = 'shielded'\n"
    (package / "__init__.py").write_bytes(source)
    interpreter = venv / "bin" / "python"
    interpreter.parent.mkdir()
    interpreter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    os.chmod(interpreter, 0o755)
    body = (
        b"# -*- coding: utf-8 -*-\n"
        b"from echo_veil.agent_cli import main\n"
        b"if __name__ == '__main__':\n"
        b"    raise SystemExit(main())\n"
    )
    executable = venv / "bin" / "echo-veil-agent"
    executable.write_bytes(f"#!{interpreter}\n".encode() + body)
    os.chmod(executable, 0o755)

    wheel = tmp_path / "echo_veil-0.7.0-py3-none-any.whl"
    with zipfile.ZipFile(wheel, "w") as bundle:
        bundle.writestr("echo_veil/__init__.py", source)
        bundle.writestr(
            "echo_veil-0.7.0.dist-info/entry_points.txt",
            "[console_scripts]\necho-veil-agent = echo_veil.agent_cli:main\n",
        )
    os.chmod(wheel, 0o600)
    wheel_digest = hashlib.sha256(wheel.read_bytes()).hexdigest()
    (dist_info / "METADATA").write_text(
        "Metadata-Version: 2.1\nName: echo-veil\nVersion: 0.7.0\n",
        encoding="utf-8",
    )
    (dist_info / "direct_url.json").write_text(
        json.dumps(
            {
                "url": wheel.as_uri(),
                "archive_info": {"hash": f"sha256={wheel_digest}"},
            }
        ),
        encoding="utf-8",
    )
    lock = {
        "python": {
            "distribution": "echo-veil",
            "version": "0.7.0",
            "wheel_sha256": wheel_digest,
            "console_body_sha256": hashlib.sha256(body).hexdigest(),
        }
    }
    return executable, lock


def test_python_artifact_requires_exact_wheel_source_and_console_body(
    tmp_path: Path,
) -> None:
    executable, lock = _write_python_install(tmp_path)

    result = verify_python_artifact(str(executable), lock)

    assert result["artifact_bound"] is True
    assert result["installed_files_verified"] == 1
    (
        executable.parent.parent / "lib/python3.14/site-packages/echo_veil/__init__.py"
    ).write_text(
        "VALUE = 'changed'\n",
        encoding="utf-8",
    )
    with pytest.raises(DeploymentError, match="differs from its wheel"):
        verify_python_artifact(str(executable), lock)
