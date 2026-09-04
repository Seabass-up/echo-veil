from __future__ import annotations

import hashlib
import json
import shutil
import stat
from argparse import Namespace
from contextlib import contextmanager
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

from echo_veil import guarded_runner


def _args(host: str, **overrides: object) -> Namespace:
    values: dict[str, object] = {
        "host": host,
        "host_command": f"/opt/echo-test/{host}",
        "echo_command": "/opt/echo-test/echo-veil-agent",
        "echo_hook_command": None,
        "state_dir": None,
        "broker_socket": None,
        "profile": "echo-universal-qwen3-v1",
        "scope": "local-user",
        "embedding_model": "qwen3-embedding:latest",
        "embedding_dimension": 1024,
        "ollama_url": "http://127.0.0.1:11434",
        "cwd": None,
        "model": None,
        "output_format": "stream-json" if host == "droid" else "text",
        "sandbox": None,
        "allow_non_git": False,
        "codex_interactive": False,
        "codex_plugin_dir": None,
        "codex_artifact_authority_id": None,
        "print_codex_artifact_receipt": False,
        "reasoning_effort": None,
        "auto": None,
        "provider": None,
        "max_turns": None,
        "hermes_plugin_dir": None,
        "pi_extension_dir": None,
        "pi_artifact_authority_id": None,
        "goose_builtin": [],
    }
    values.update(overrides)
    return Namespace(**values)


def _ready_doctor(
    preflight_authority_id: str = "sha256:" + "e" * 64,
) -> dict[str, object]:
    return {
        "adapter_ready": True,
        "local_protection_ready": True,
        "profile": "echo-universal-qwen3-v1",
        "protection_policy": "required",
        "security_schema": "scoped-v2",
        "scope_bound": True,
        "writer_serialization": "profile-sqlite-lease",
        "plaintext_fallback_attempts": 0,
        "reconciliation_backlog": 0,
        "quarantined_records": 0,
        "preflight_authority_id": preflight_authority_id,
        "readiness": {
            "healthy": True,
            "retrieval_wired": True,
            "persistence_wired": True,
            "restart_restored": True,
            "layer_contract_wired": True,
            "context_trace_wired": True,
            "competing_memory_wired": True,
            "content_policy_wired": True,
        },
        "memory_layers": {"all_records_shielded": True},
        "retrieval": {
            "unindexed_payload_count": 0,
            "answerability_gate": "semantic-predicate-v1",
        },
        "embedding": {
            "backend": "ollama",
            "model": "qwen3-embedding:latest",
            "dimension": 1024,
            "semantic": True,
        },
    }


def test_protected_root_prompt_keeps_memory_and_user_prompt_delimited() -> None:
    result = guarded_runner._protected_root_prompt(
        "ECHO VEIL REQUIRED MEMORY PREFLIGHT\nMEMORY_EVIDENCE_JSON={}",
        "Do the current task.",
    ).decode("utf-8")

    assert result.startswith("ECHO_VEIL_PROTECTED_ROOT_CONTEXT_BEGIN")
    assert "ECHO_VEIL_PROTECTED_ROOT_CONTEXT_END" in result
    assert "CURRENT_USER_PROMPT_BEGIN\nDo the current task." in result
    assert result.endswith("CURRENT_USER_PROMPT_END")


def test_hermes_prompt_is_bound_to_one_launch_nonce() -> None:
    nonce = "a" * 32

    result = guarded_runner._bind_hermes_prompt(b"protected", nonce)

    assert result == (
        f"{guarded_runner.HERMES_LAUNCH_MARKER}{nonce}\nprotected".encode()
    )
    with pytest.raises(ValueError, match="nonce"):
        guarded_runner._bind_hermes_prompt(b"protected", "not-a-nonce")


def test_hermes_plugin_digests_bind_the_reviewed_repository_source() -> None:
    plugin_dir = (
        Path(__file__).resolve().parents[1] / "integrations" / "hermes" / "plugin"
    )

    assert guarded_runner.HERMES_PLUGIN_DIGESTS == {
        name: hashlib.sha256((plugin_dir / name).read_bytes()).hexdigest()
        for name in guarded_runner.HERMES_PLUGIN_FILES
    }


def test_guarded_prompt_reader_rejects_empty_and_oversized_input() -> None:
    with pytest.raises(ValueError, match="empty"):
        guarded_runner._read_prompt(BytesIO(b" \n"))
    with pytest.raises(ValueError, match="limit"):
        guarded_runner._read_prompt(
            BytesIO(b"x" * (guarded_runner.MAX_GUARDED_INPUT_BYTES + 1))
        )


def test_host_environment_withholds_unrelated_secrets() -> None:
    result = guarded_runner._host_environment(
        {
            "PATH": "/bin",
            "HOME": "/tmp/home",
            "CODEX_HOME": "/tmp/codex",
            "OPENAI_API_KEY": "required-provider-secret",
            "ECHO_VEIL_FORCE_AGENT_PREFLIGHT_FAILURE": "must-not-pass",
            "UNRELATED_SECRET": "must-not-pass",
        }
    )

    assert result == {
        "PATH": "/bin",
        "HOME": "/tmp/home",
        "OPENAI_API_KEY": "required-provider-secret",
    }


def test_codex_environment_exposes_only_owner_auth_and_clean_home(
    tmp_path: Path,
) -> None:
    source_home = tmp_path / "source"
    source_home.mkdir()
    auth = source_home / "auth.json"
    auth.write_text("opaque-test-auth", encoding="utf-8")
    auth.chmod(0o600)

    with guarded_runner._isolated_codex_environment(
        {
            "CODEX_HOME": str(source_home),
            "HOME": str(tmp_path),
            "PATH": "/bin",
            "OPENAI_API_KEY": "must-not-pass-with-auth-file",
            "AWS_SECRET_ACCESS_KEY": "must-not-pass",
            "UNRELATED_SECRET": "must-not-pass",
        }
    ) as environment:
        isolated_home = Path(environment["CODEX_HOME"])
        assert isolated_home != source_home
        assert stat.S_IMODE(isolated_home.stat().st_mode) == 0o700
        assert not (isolated_home / "auth.json").is_symlink()
        assert (isolated_home / "auth.json").read_text(encoding="utf-8") == (
            "opaque-test-auth"
        )
        assert stat.S_IMODE((isolated_home / "auth.json").stat().st_mode) == 0o600
        assert list(isolated_home.iterdir()) == [isolated_home / "auth.json"]
        assert environment["HOME"] == str(isolated_home)
        assert environment["XDG_CONFIG_HOME"] == str(isolated_home)
        assert "OPENAI_API_KEY" not in environment
        assert "AWS_SECRET_ACCESS_KEY" not in environment
        assert "UNRELATED_SECRET" not in environment

    assert not isolated_home.exists()


def test_codex_environment_uses_only_openai_key_without_auth_file(
    tmp_path: Path,
) -> None:
    source_home = tmp_path / "source"
    source_home.mkdir()

    with guarded_runner._isolated_codex_environment(
        {
            "CODEX_HOME": str(source_home),
            "HOME": str(tmp_path),
            "PATH": "/bin",
            "OPENAI_API_KEY": "one-required-key",
            "ANTHROPIC_API_KEY": "must-not-pass",
        }
    ) as environment:
        assert environment["OPENAI_API_KEY"] == "one-required-key"
        assert "ANTHROPIC_API_KEY" not in environment


def test_codex_environment_rejects_broad_auth_permissions(tmp_path: Path) -> None:
    auth = tmp_path / "auth.json"
    auth.write_text("opaque-test-auth", encoding="utf-8")
    auth.chmod(0o644)

    with pytest.raises(RuntimeError, match="permissions"):
        with guarded_runner._isolated_codex_environment(
            {"CODEX_HOME": str(tmp_path), "HOME": str(tmp_path), "PATH": "/bin"}
        ):
            pytest.fail("insecure auth file was exposed")


def test_codex_argv_is_ephemeral_and_disables_unhookable_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args(
        "codex",
        model="gpt-test",
        output_format="json",
        sandbox="workspace-write",
        cwd="/workspace",
        allow_non_git=True,
    )

    result = guarded_runner._host_argv(args)

    assert result[:4] == [
        "/opt/echo-test/codex",
        "--ask-for-approval",
        "never",
        "exec",
    ]
    assert result.index("--ask-for-approval") < result.index("exec")
    assert "--ignore-user-config" in result
    assert "--strict-config" in result
    configs = [
        result[index + 1] for index, value in enumerate(result) if value == "--config"
    ]
    assert 'mcp_servers.echo_veil.command="/opt/echo-test/echo-veil-agent"' in configs
    assert any(
        value.startswith("mcp_servers.echo_veil.args=[")
        and '"--caller","codex"' in value
        and value.endswith(',"mcp"]')
        for value in configs
    )
    assert "mcp_servers.echo_veil.enabled=true" in configs
    assert "mcp_servers.echo_veil.required=true" in configs
    for feature in guarded_runner.CODEX_DISABLED_FEATURES:
        assert ["--disable", feature] == result[
            result.index(feature) - 1 : result.index(feature) + 1
        ]
    assert "--ignore-rules" in result
    assert ["--ask-for-approval", "never"] == result[
        result.index("--ask-for-approval") : result.index("--ask-for-approval") + 2
    ]
    assert result[-9:] == [
        "workspace-write",
        "--color",
        "never",
        "--skip-git-repo-check",
        "--json",
        "-C",
        "/workspace",
        "--model",
        "gpt-test",
    ]
    assert "--dangerously-bypass-approvals-and-sandbox" not in result
    assert "--dangerously-bypass-hook-trust" not in result


def test_codex_defaults_to_read_only_json_and_rejects_other_host_options() -> None:
    args = _args("codex", output_format=None, model="gpt-test")

    guarded_runner._validate_host_options(args)

    assert args.output_format == "json"
    assert args.sandbox == "read-only"

    args.provider = "ollama"
    with pytest.raises(ValueError, match="non-Codex"):
        guarded_runner._validate_host_options(args)

    args = _args("codex", output_format="stream-json")
    with pytest.raises(ValueError, match="text or json"):
        guarded_runner._validate_host_options(args)


def test_interactive_codex_profile_is_singular_and_artifact_bound(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source_home = tmp_path / "source-home"
    source_home.mkdir()
    auth = source_home / "auth.json"
    auth.write_text("opaque-test-auth", encoding="utf-8")
    auth.chmod(0o600)
    root = Path(__file__).resolve().parents[1]
    payloads = {
        name: (root / name).read_bytes()
        for name in (
            ".agents/plugins/marketplace.json",
            ".codex-plugin/plugin.json",
            ".mcp.json",
            "hooks/hooks.json",
            "skills/echo-veil-memory/SKILL.md",
            "skills/echo-veil-memory/agents/openai.yaml",
        )
    }
    bundle = guarded_runner.CodexArtifactBundle(
        authority_id="sha256:" + "a" * 64,
        plugin_payloads=payloads,
        receipt={},
    )
    args = _args(
        "codex",
        codex_interactive=True,
        cwd=str(tmp_path),
        echo_command="/bin/echo",
        echo_hook_command="/bin/echo",
        model="gpt-test",
        output_format="text",
        sandbox="read-only",
        state_dir=tmp_path / "echo-state",
    )
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: str(
            Path(explicit or f"/resolved/{default}").resolve()
        ),
    )

    argv = guarded_runner._host_argv(args)
    assert argv[0] == "/opt/echo-test/codex"
    assert "exec" not in argv
    assert ["--profile", guarded_runner.CODEX_PROFILE_NAME] == argv[1:3]
    assert "--dangerously-bypass-hook-trust" in argv
    assert "--enable" not in argv
    for feature in guarded_runner.CODEX_INTERACTIVE_DISABLED_FEATURES:
        assert ["--disable", feature] == argv[
            argv.index(feature) - 1 : argv.index(feature) + 1
        ]

    with guarded_runner._isolated_codex_environment(
        {
            "CODEX_HOME": str(source_home),
            "HOME": str(tmp_path),
            "PATH": "/bin",
            "OPENAI_API_KEY": "must-not-pass",
        },
        args=args,
        bundle=bundle,
        interactive=True,
    ) as environment:
        home = Path(environment["CODEX_HOME"])
        profile = (home / "echo-veil.config.toml").read_text(encoding="utf-8")
        base = (home / "config.toml").read_text(encoding="utf-8")
        assert 'trust_level = "untrusted"' in base
        assert "apps = false" in profile
        assert "memories = false" in profile
        assert "chronicle = false" in profile
        assert "enable_mcp_apps = false" in profile
        assert "goals = false" in profile
        assert "multi_agent = false" in profile
        assert "plugin_sharing = false" in profile
        assert "remote_plugin = false" in profile
        assert "plugins = false" in profile
        assert "[apps._default]\nenabled = false" in profile
        assert "[plugins." not in profile
        assert "[marketplaces." not in profile
        assert "[mcp_servers.echo_veil]" in profile
        assert '"--state-dir"' in profile
        assert str(tmp_path / "echo-state") in profile
        assert 'inherit = "core"' in profile
        assert '"PATH" = "include"' in profile
        assert "mem@openai-curated" not in profile
        assert environment["ECHO_VEIL_CODEX_ARTIFACT_AUTHORITY_ID"] == (
            bundle.authority_id
        )
        assert "OPENAI_API_KEY" not in environment
        installed_assets = {
            "hooks/hooks.json": home / "hooks.json",
            "skills/echo-veil-memory/SKILL.md": (
                home / "skills" / "echo-veil-memory" / "SKILL.md"
            ),
            "skills/echo-veil-memory/agents/openai.yaml": (
                home / "skills" / "echo-veil-memory" / "agents" / "openai.yaml"
            ),
        }
        for name, installed in installed_assets.items():
            payload = payloads[name]
            assert installed.read_bytes() == payload
            assert stat.S_IMODE(installed.stat().st_mode) == 0o600
        assert not (home / "echo-veil-plugin").exists()

    assert not home.exists()


def test_droid_argv_uses_stdin_and_rejects_goose_options(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args(
        "droid",
        model="local-model",
        reasoning_effort="high",
        auto="medium",
        cwd="/workspace",
    )

    assert guarded_runner._host_argv(args) == [
        "/opt/echo-test/droid",
        "exec",
        "--output-format",
        "stream-json",
        "--disable-builtin-skills",
        "--disabled-tools",
        "Task",
        "--cwd",
        "/workspace",
        "--model",
        "local-model",
        "--reasoning-effort",
        "high",
        "--auto",
        "medium",
    ]
    args.provider = "ollama"
    with pytest.raises(ValueError, match="non-Droid"):
        guarded_runner._validate_host_options(args)


def test_goose_argv_is_ephemeral_and_loads_only_echo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args(
        "goose",
        provider="ollama",
        model="local-model",
        max_turns=3,
        goose_builtin=["developer"],
    )

    result = guarded_runner._host_argv(args)

    assert result[:6] == [
        "/opt/echo-test/goose",
        "run",
        "--instructions",
        "-",
        "--no-profile",
        "--no-session",
    ]
    assert "--with-extension" in result
    extension = result[result.index("--with-extension") + 1]
    assert extension.startswith("/opt/echo-test/echo-veil-agent ")
    assert "--caller goose" in extension
    assert result[-8:] == [
        "--provider",
        "ollama",
        "--model",
        "local-model",
        "--max-turns",
        "3",
        "--with-builtin",
        "developer",
    ]


def test_goose_mcp_uses_the_same_explicit_state_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args("goose", state_dir=tmp_path)

    result = guarded_runner._host_argv(args)
    extension = result[result.index("--with-extension") + 1]

    assert f"--state-dir {tmp_path}" in extension


def test_hermes_argv_uses_only_the_registered_fail_closed_command(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args(
        "hermes",
        provider=guarded_runner.HERMES_LOCAL_PROVIDER,
        model="qwen3.6:35b-mlx",
    )

    assert guarded_runner._host_argv(args) == [
        "/opt/echo-test/hermes",
        "echo-veil-run",
        "--provider",
        guarded_runner.HERMES_LOCAL_PROVIDER,
        "--model",
        "qwen3.6:35b-mlx",
    ]


def test_hermes_requires_canonical_profile_explicit_model_and_text_output() -> None:
    args = _args("hermes", output_format=None)
    with pytest.raises(ValueError, match="model"):
        guarded_runner._validate_host_options(args)

    args = _args(
        "hermes",
        model="qwen3.6:35b-mlx",
        output_format=None,
    )
    guarded_runner._validate_host_options(args)
    assert args.output_format == "text"
    assert args.provider == guarded_runner.HERMES_LOCAL_PROVIDER

    args.embedding_dimension = 4096
    with pytest.raises(ValueError, match="canonical"):
        guarded_runner._validate_host_options(args)

    args = _args(
        "hermes",
        provider="remote-provider",
        model="qwen3.6:35b-mlx",
        output_format=None,
    )
    with pytest.raises(ValueError, match="local provider"):
        guarded_runner._validate_host_options(args)

    args = _args(
        "hermes",
        provider=guarded_runner.HERMES_LOCAL_PROVIDER,
        model="qwen3.6:35b-mlx",
        output_format="json",
    )
    with pytest.raises(ValueError, match="must be text"):
        guarded_runner._validate_host_options(args)


def test_hermes_environment_contains_only_digest_bound_plugin_and_config(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-plugin"
    source.mkdir(mode=0o700)
    payloads = {
        "__init__.py": b"# reviewed plugin\n",
        "plugin.yaml": b"name: echo-veil-shield\n",
    }
    for name, payload in payloads.items():
        path = source / name
        path.write_bytes(payload)
        path.chmod(0o600)
    monkeypatch.setattr(
        guarded_runner,
        "HERMES_PLUGIN_DIGESTS",
        {
            name: hashlib.sha256(payload).hexdigest()
            for name, payload in payloads.items()
        },
    )
    args = _args(
        "hermes",
        echo_command="/bin/echo",
        hermes_plugin_dir=str(source),
        provider=guarded_runner.HERMES_LOCAL_PROVIDER,
        model="qwen3.6:35b-mlx",
        state_dir=tmp_path / "echo-state",
    )
    nonce = "b" * 32
    resolved_echo = Path(args.echo_command).resolve(strict=True)

    with guarded_runner._isolated_hermes_environment(
        args,
        nonce,
        {
            "HOME": str(tmp_path),
            "PATH": "/bin",
            "UNRELATED_SECRET": "must-not-pass",
        },
    ) as environment:
        home = Path(environment["HERMES_HOME"])
        assert stat.S_IMODE(home.stat().st_mode) == 0o700
        assert environment[guarded_runner.HERMES_LAUNCH_NONCE_ENV] == nonce
        assert environment["ECHO_VEIL_STATE_DIR"] == str(args.state_dir)
        assert "UNRELATED_SECRET" not in environment
        for name, payload in payloads.items():
            installed = home / "plugins" / "echo-veil-shield" / name
            assert installed.read_bytes() == payload
            assert stat.S_IMODE(installed.stat().st_mode) == 0o600
        config = (home / "config.yaml").read_text(encoding="utf-8")
        assert "memory_enabled: false" in config
        assert "user_profile_enabled: false" in config
        assert "echo-veil-shield" in config
        assert json.dumps(str(resolved_echo)) in config
        assert '"--caller","hermes"' in config
        assert (home / "bin" / "echo-veil-agent").resolve() == resolved_echo

    assert not home.exists()


def test_hermes_environment_rejects_plugin_digest_drift(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    source = tmp_path / "source-plugin"
    source.mkdir(mode=0o700)
    for name in guarded_runner.HERMES_PLUGIN_FILES:
        path = source / name
        path.write_text("tampered", encoding="utf-8")
        path.chmod(0o600)
    args = _args(
        "hermes",
        echo_command="/bin/echo",
        hermes_plugin_dir=str(source),
        provider=guarded_runner.HERMES_LOCAL_PROVIDER,
        model="qwen3.6:35b-mlx",
    )

    with pytest.raises(RuntimeError, match="digest"):
        with guarded_runner._isolated_hermes_environment(
            args,
            "c" * 32,
            {"HOME": str(tmp_path), "PATH": "/bin"},
        ):
            pytest.fail("digest drift was accepted")


def _pi_artifact() -> tuple[Path, str]:
    root = Path(__file__).resolve().parents[1] / "integrations" / "pi"
    receipt = json.loads((root / "artifact-receipt.json").read_text(encoding="utf-8"))
    return root, receipt["artifact_authority_id"]


def test_pi_artifact_receipt_blocks_one_byte_drift(tmp_path: Path) -> None:
    source, authority_id = _pi_artifact()

    assert guarded_runner._verify_pi_artifact(source, authority_id) == authority_id

    copied = tmp_path / "pi"
    copied.mkdir(mode=0o700)
    for name in (*guarded_runner.PI_ARTIFACT_FILES, "artifact-receipt.json"):
        destination = copied / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source / name, destination)
    with (copied / "extensions" / "index.ts").open("ab") as stream:
        stream.write(b"\n")

    with pytest.raises(RuntimeError, match="digest mismatch"):
        guarded_runner._verify_pi_artifact(copied, authority_id)


def test_pi_executable_version_is_exactly_qualified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def completed(stdout: bytes, returncode: int = 0) -> SimpleNamespace:
        return SimpleNamespace(stdout=stdout, stderr=b"", returncode=returncode)

    monkeypatch.setattr(
        guarded_runner.subprocess,
        "run",
        lambda *args, **kwargs: completed(b"0.84.4\n"),
    )
    guarded_runner._verify_pi_version("/verified/pi")

    monkeypatch.setattr(
        guarded_runner.subprocess,
        "run",
        lambda *args, **kwargs: completed(b"0.84.2\n"),
    )
    with pytest.raises(RuntimeError, match="version is not qualified"):
        guarded_runner._verify_pi_version("/verified/pi")


def test_pi_argv_is_ephemeral_and_loads_only_the_pinned_echo_extension(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args(
        "pi",
        provider="openai",
        model="gpt-test",
        pi_extension_dir="/reviewed/pi",
    )

    result = guarded_runner._host_argv(args)

    assert result[:8] == [
        "/opt/echo-test/pi",
        "--print",
        "--mode",
        "text",
        "--provider",
        "openai",
        "--model",
        "gpt-test",
    ]
    assert "--no-session" in result
    assert "--no-extensions" in result
    assert "--no-skills" in result
    assert "--no-prompt-templates" in result
    assert "--no-context-files" in result
    assert "--no-builtin-tools" in result
    assert result[result.index("--extension") + 1] == (
        "/reviewed/pi/extensions/index.ts"
    )
    assert result[result.index("--tools") + 1] == ",".join(guarded_runner.PI_ECHO_TOOLS)


def test_pi_environment_exposes_one_provider_and_exact_echo_pins(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )
    args = _args(
        "pi",
        provider="openai",
        model="gpt-test",
        state_dir=tmp_path / "echo-state",
    )
    artifact_id = "sha256:" + "a" * 64
    preflight_id = "sha256:" + "b" * 64

    with guarded_runner._isolated_pi_environment(
        args,
        artifact_authority_id=artifact_id,
        preflight_authority_id=preflight_id,
        environ={
            "HOME": str(tmp_path / "ambient"),
            "PATH": "/bin",
            "OPENAI_API_KEY": "only-provider-secret",
            "ANTHROPIC_API_KEY": "must-not-pass",
            "AWS_SECRET_ACCESS_KEY": "must-not-pass",
            "UNRELATED_SECRET": "must-not-pass",
        },
    ) as environment:
        isolated_home = Path(environment["HOME"])
        assert isolated_home != tmp_path / "ambient"
        assert stat.S_IMODE(isolated_home.stat().st_mode) == 0o700
        assert environment["PI_CODING_AGENT_DIR"] == str(isolated_home)
        assert environment["XDG_CONFIG_HOME"] == str(isolated_home)
        assert environment["XDG_DATA_HOME"] == str(isolated_home)
        assert environment["XDG_STATE_HOME"] == str(isolated_home)
        assert environment["PI_OFFLINE"] == "1"
        assert environment["PI_TELEMETRY"] == "0"
        assert environment["OPENAI_API_KEY"] == "only-provider-secret"
        assert "ANTHROPIC_API_KEY" not in environment
        assert "AWS_SECRET_ACCESS_KEY" not in environment
        assert "UNRELATED_SECRET" not in environment
        assert environment["ECHO_VEIL_PI_ARTIFACT_AUTHORITY_ID"] == artifact_id
        assert environment["ECHO_VEIL_PREFLIGHT_AUTHORITY_ID"] == preflight_id
        assert environment["ECHO_VEIL_STATE_DIR"] == str(args.state_dir)

    assert not isolated_home.exists()


def test_pi_requires_explicit_model_provider_and_text_output() -> None:
    root, authority_id = _pi_artifact()
    args = _args(
        "pi",
        provider="ollama",
        model="qwen3.5-test",
        output_format=None,
        pi_extension_dir=str(root),
        pi_artifact_authority_id=authority_id,
    )
    guarded_runner._validate_host_options(args)
    assert args.output_format == "text"

    args = _args("pi", provider=None, model="qwen3.5-test")
    with pytest.raises(ValueError, match="provider"):
        guarded_runner._validate_host_options(args)
    args = _args("pi", provider="ollama", model=None)
    with pytest.raises(ValueError, match="model"):
        guarded_runner._validate_host_options(args)
    args = _args(
        "pi",
        provider="ollama",
        model="qwen3.5-test",
        output_format="json",
    )
    with pytest.raises(ValueError, match="must be text"):
        guarded_runner._validate_host_options(args)


def test_preflight_neutralizes_ambient_state_root(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}
    args = _args("goose", state_dir=None)
    monkeypatch.setenv("ECHO_VEIL_STATE_DIR", str(tmp_path / "ambient"))

    class FakeParser:
        def set_defaults(self, **values: object) -> None:
            observed["defaults"] = values

        def parse_args(self, argv: list[str]) -> Namespace:
            observed["argv"] = argv
            return Namespace()

    class FakeMemory:
        def __enter__(self) -> FakeMemory:
            return self

        def __exit__(self, *args: object) -> None:
            del args

    monkeypatch.setattr(guarded_runner, "build_agent_parser", FakeParser)
    monkeypatch.setattr(
        guarded_runner, "_open_memory", lambda runtime_args: FakeMemory()
    )
    monkeypatch.setattr(
        guarded_runner,
        "prepare_preflight",
        lambda memory, prompt, **kwargs: "protected",
    )

    assert guarded_runner._preflight_context(args, "current prompt") == "protected"
    expected = guarded_runner._effective_state_dir(args)
    assert observed["defaults"] == {"state_dir": expected}
    assert observed["defaults"] != {"state_dir": tmp_path / "ambient"}


def test_broker_preflight_and_authority_do_not_reopen_the_profile(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = Path("/private/tmp/echo-veil-test.sock")
    args = _args("codex", broker_socket=socket_path)
    calls: list[tuple[str, dict[str, object], str]] = []
    authority_id = "sha256:" + "e" * 64

    class FakeBrokerClient:
        def __init__(self, path: Path, *, caller: str) -> None:
            assert path == socket_path
            self.caller = caller

        def call(self, action: str, arguments: dict[str, object]) -> dict[str, object]:
            calls.append((action, arguments, self.caller))
            if action == "doctor":
                return _ready_doctor(authority_id)
            return {
                "preflight_ready": True,
                "semantic": True,
                "profile": args.profile,
                "scope": args.scope,
                "context": "protected context",
            }

    monkeypatch.setattr(guarded_runner, "BrokerClient", FakeBrokerClient)
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/verified/{default}",
    )
    monkeypatch.setattr(
        guarded_runner,
        "_open_memory",
        lambda _args: pytest.fail("brokered runner reopened the profile"),
    )

    assert guarded_runner._preflight_context(args, "current prompt") == (
        "protected context"
    )
    assert guarded_runner._preflight_authority_id(args) == authority_id
    mcp_argv = guarded_runner._echo_mcp_argv(args, caller="codex")
    assert mcp_argv[mcp_argv.index("--broker-socket") + 1] == str(socket_path)
    assert [call[0] for call in calls] == ["preflight", "doctor"]
    assert all(call[2] == "codex" for call in calls)


def test_broker_authority_rejects_degraded_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    args = _args(
        "pi",
        broker_socket=Path("/private/tmp/echo-veil-test.sock"),
    )

    class DegradedBrokerClient:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def call(self, _action: str, _arguments: object) -> dict[str, object]:
            doctor = _ready_doctor()
            doctor["adapter_ready"] = False
            return doctor

    monkeypatch.setattr(guarded_runner, "BrokerClient", DegradedBrokerClient)

    with pytest.raises(RuntimeError, match="adapter_ready"):
        guarded_runner._preflight_authority_id(args)


def test_codex_artifact_contract_binds_broker_endpoint_and_signing_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    socket_path = Path("/private/tmp/echo-veil-test.sock")
    args = _args(
        "codex",
        broker_socket=socket_path,
        model="gpt-test",
        sandbox="workspace-write",
    )
    authority_id = "sha256:" + "f" * 64
    monkeypatch.setattr(
        guarded_runner,
        "_preflight_authority_id",
        lambda _args: authority_id,
    )

    contract = guarded_runner._codex_configuration_contract(args)

    assert contract["broker_required"] is True
    assert contract["broker_preflight_authority_id"] == authority_id
    assert str(socket_path) not in json.dumps(contract)
    assert str(contract["broker_authority_id"]).startswith("sha256:")


@pytest.mark.parametrize("host", guarded_runner.GUARDED_HOSTS)
def test_main_fails_before_host_execution_when_preflight_fails(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    host: str,
) -> None:
    called = False

    def fail_preflight(args: Namespace, prompt: str) -> str:
        del args, prompt
        raise RuntimeError("private detail")

    def run_host(*args: object, **kwargs: object) -> int:
        nonlocal called
        del args, kwargs
        called = True
        return 0

    monkeypatch.setattr(guarded_runner, "_preflight_context", fail_preflight)
    monkeypatch.setattr(
        guarded_runner,
        "_preflight_authority_id",
        lambda args: (_ for _ in ()).throw(RuntimeError("private detail")),
    )
    monkeypatch.setattr(
        guarded_runner,
        "_verify_pi_artifact",
        lambda directory, authority: "sha256:" + "a" * 64,
    )
    monkeypatch.setattr(guarded_runner, "_verify_pi_version", lambda command: None)
    monkeypatch.setattr(
        guarded_runner,
        "_build_codex_artifact",
        lambda args: guarded_runner.CodexArtifactBundle(
            authority_id="sha256:" + "c" * 64,
            plugin_payloads={},
            receipt={},
        ),
    )
    monkeypatch.setattr(
        guarded_runner,
        "verify_codex_artifact_pin",
        lambda bundle, authority: None,
    )
    monkeypatch.setattr(guarded_runner, "_verify_codex_version", lambda command: None)
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/verified/{default}",
    )
    monkeypatch.setattr(guarded_runner, "_run_host", run_host)

    command = [
        host,
        "--host-command",
        str(Path("/bin/echo")),
    ]
    if host == "codex":
        command.extend(["--model", "gpt-test"])
    if host == "pi":
        root, authority_id = _pi_artifact()
        command.extend(
            [
                "--provider",
                "ollama",
                "--model",
                "qwen3.5-test",
                "--pi-extension-dir",
                str(root),
                "--pi-artifact-authority-id",
                authority_id,
            ]
        )

    result = guarded_runner.main(
        command,
        stream=BytesIO(b"Do not reach the model."),
    )

    assert result == 2
    assert called is False
    captured = capsys.readouterr()
    assert "private detail" not in captured.err
    assert guarded_runner.REQUIRED_PREFLIGHT_FAILURE in captured.err


def test_main_sends_protected_context_only_over_child_stdin(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    monkeypatch.setattr(
        guarded_runner,
        "_preflight_context",
        lambda args, prompt: "ECHO VEIL REQUIRED MEMORY PREFLIGHT",
    )
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )

    def fake_run(
        argv: list[str],
        *,
        input: bytes,
        cwd: str | None,
        env: dict[str, str],
        shell: bool,
        check: bool,
    ) -> SimpleNamespace:
        observed.update(
            {
                "argv": argv,
                "input": input,
                "cwd": cwd,
                "env": env,
                "shell": shell,
                "check": check,
            }
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(guarded_runner.subprocess, "run", fake_run)
    monkeypatch.setattr(
        guarded_runner,
        "_isolated_codex_environment",
        lambda: pytest.fail("Goose must not request a Codex home"),
    )

    result = guarded_runner.main(
        [
            "goose",
            "--host-command",
            "/opt/echo-test/goose",
            "--echo-command",
            "/opt/echo-test/echo-veil-agent",
        ],
        stream=BytesIO(b"Use protected memory."),
    )

    assert result == 0
    assert "Use protected memory." not in " ".join(observed["argv"])  # type: ignore[arg-type]
    assert b"CURRENT_USER_PROMPT_BEGIN\nUse protected memory." in observed["input"]  # type: ignore[operator]
    assert observed["shell"] is False
    assert observed["check"] is False


def test_pi_main_defers_semantic_gate_to_verified_extension_input_hook(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}
    root, artifact_id = _pi_artifact()
    preflight_id = "sha256:" + "b" * 64

    monkeypatch.setattr(
        guarded_runner,
        "_preflight_context",
        lambda args, prompt: pytest.fail(
            "Pi must use the extension's single preflight-v2 RPC"
        ),
    )
    monkeypatch.setattr(
        guarded_runner,
        "_preflight_authority_id",
        lambda args: preflight_id,
    )
    monkeypatch.setattr(guarded_runner, "_verify_pi_version", lambda command: None)
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/resolved/{default}",
    )

    def fake_run(
        argv: list[str],
        *,
        input: bytes,
        cwd: str | None,
        env: dict[str, str],
        shell: bool,
        check: bool,
    ) -> SimpleNamespace:
        observed.update(
            {
                "argv": argv,
                "input": input,
                "cwd": cwd,
                "env": env,
                "shell": shell,
                "check": check,
            }
        )
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(guarded_runner.subprocess, "run", fake_run)

    result = guarded_runner.main(
        [
            "pi",
            "--host-command",
            "/opt/echo-test/pi",
            "--echo-command",
            "/opt/echo-test/echo-veil-agent",
            "--state-dir",
            str(tmp_path / "echo-state"),
            "--provider",
            "ollama",
            "--model",
            "qwen3.5-test",
            "--pi-extension-dir",
            str(root),
            "--pi-artifact-authority-id",
            artifact_id,
        ],
        stream=BytesIO(b"Use protected memory privately."),
    )

    assert result == 0
    assert observed["input"] == b"Use protected memory privately."
    assert "Use protected memory privately." not in " ".join(observed["argv"])  # type: ignore[arg-type]
    environment = observed["env"]  # type: ignore[assignment]
    assert environment["ECHO_VEIL_PI_ARTIFACT_AUTHORITY_ID"] == artifact_id  # type: ignore[index]
    assert environment["ECHO_VEIL_PREFLIGHT_AUTHORITY_ID"] == preflight_id  # type: ignore[index]
    assert observed["shell"] is False


def test_interactive_codex_starts_without_reading_or_forwarding_a_prompt(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    observed: dict[str, object] = {}
    bundle = guarded_runner.CodexArtifactBundle(
        authority_id="sha256:" + "d" * 64,
        plugin_payloads={},
        receipt={},
    )
    monkeypatch.setattr(guarded_runner, "_build_codex_artifact", lambda args: bundle)
    monkeypatch.setattr(
        guarded_runner,
        "verify_codex_artifact_pin",
        lambda value, authority: None,
    )
    monkeypatch.setattr(guarded_runner, "_verify_codex_version", lambda command: None)
    monkeypatch.setattr(
        guarded_runner,
        "_resolve_executable",
        lambda explicit, default: explicit or f"/verified/{default}",
    )
    monkeypatch.setattr(
        guarded_runner,
        "_read_prompt",
        lambda stream: pytest.fail("interactive Codex must read in its own TUI"),
    )
    monkeypatch.setattr(
        guarded_runner,
        "_host_argv",
        lambda args: ["/verified/codex", "--profile", "echo-veil"],
    )

    @contextmanager
    def environment(**kwargs: object):
        del kwargs
        yield {"PATH": "/bin", "CODEX_HOME": "/isolated"}

    monkeypatch.setattr(guarded_runner, "_isolated_codex_environment", environment)
    monkeypatch.setattr(
        guarded_runner,
        "_run_host",
        lambda *args, **kwargs: pytest.fail("interactive Codex cannot use piped mode"),
    )

    def run_interactive(
        argv: list[str],
        *,
        cwd: str | None,
        environment: dict[str, str],
    ) -> int:
        observed.update({"argv": argv, "cwd": cwd, "environment": environment})
        return 0

    monkeypatch.setattr(guarded_runner, "_run_interactive_host", run_interactive)

    result = guarded_runner.main(
        [
            "codex",
            "--codex-interactive",
            "--host-command",
            "/verified/codex",
            "--model",
            "gpt-test",
            "--codex-artifact-authority-id",
            bundle.authority_id,
            "--cwd",
            str(tmp_path),
        ],
        stream=BytesIO(b"must-not-be-read"),
    )

    assert result == 0
    assert observed["argv"] == ["/verified/codex", "--profile", "echo-veil"]
    assert observed["cwd"] == str(tmp_path)
