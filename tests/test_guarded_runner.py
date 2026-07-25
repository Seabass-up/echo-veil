from __future__ import annotations

import hashlib
import json
import stat
from argparse import Namespace
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
        "state_dir": None,
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
        "reasoning_effort": None,
        "auto": None,
        "provider": None,
        "max_turns": None,
        "hermes_plugin_dir": None,
        "goose_builtin": [],
    }
    values.update(overrides)
    return Namespace(**values)


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
            "UNRELATED_SECRET": "must-not-pass",
        }
    ) as environment:
        isolated_home = Path(environment["CODEX_HOME"])
        assert isolated_home != source_home
        assert stat.S_IMODE(isolated_home.stat().st_mode) == 0o700
        assert (isolated_home / "auth.json").is_symlink()
        assert (isolated_home / "auth.json").resolve() == auth
        assert list(isolated_home.iterdir()) == [isolated_home / "auth.json"]
        assert "UNRELATED_SECRET" not in environment

    assert not isolated_home.exists()


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

    assert result[:2] == ["/opt/echo-test/codex", "exec"]
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
    assert result[-9:] == [
        "--ephemeral",
        "--sandbox",
        "workspace-write",
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
    args = _args("codex", output_format=None)

    guarded_runner._validate_host_options(args)

    assert args.output_format == "json"
    assert args.sandbox == "read-only"

    args.provider = "ollama"
    with pytest.raises(ValueError, match="non-Codex"):
        guarded_runner._validate_host_options(args)

    args = _args("codex", output_format="stream-json")
    with pytest.raises(ValueError, match="text or json"):
        guarded_runner._validate_host_options(args)


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
    assert observed["defaults"] == {"state_dir": None}


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
    monkeypatch.setattr(guarded_runner, "_run_host", run_host)

    result = guarded_runner.main(
        [
            host,
            "--host-command",
            str(Path("/bin/echo")),
        ],
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
