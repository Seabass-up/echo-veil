from __future__ import annotations

import sys
from io import BytesIO
from types import ModuleType
from types import SimpleNamespace
from typing import Any

import pytest

from integrations.hermes import plugin


def _preflight(
    context: str = "ECHO VEIL REQUIRED MEMORY PREFLIGHT\nready",
) -> dict[str, Any]:
    return {
        "preflight_ready": True,
        "memory_authority": "echo-veil",
        "host": "hermes",
        "profile": plugin.CANONICAL_PROFILE,
        "query_source": "current_user_prompt",
        "semantic": True,
        "context": context,
    }


@pytest.fixture(autouse=True)
def _reset_plugin_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE", raising=False)
    monkeypatch.delenv(plugin.SHIELDED_RUN_NONCE_ENV, raising=False)
    with plugin._ready_lock:
        plugin._ready_turns.clear()


def test_healthy_hook_injects_context_and_execution_calls_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn",
        user_message="What is the current protected decision?",
    )
    assert injected is not None
    calls: list[dict[str, Any]] = []
    request = {
        "messages": [
            {
                "role": "user",
                "content": f"current\n\n{injected['context']}",
            }
        ]
    }

    result = plugin.on_llm_execution(
        request=request,
        next_call=lambda value: calls.append(value) or "provider-response",
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert plugin.CONTEXT_BEGIN in injected["context"]
    assert plugin.CONTEXT_END in injected["context"]
    assert result == "provider-response"
    assert calls == [request]


def test_oversized_skill_expansion_uses_bounded_preflight_query(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("INFO", logger=plugin.__name__)
    header = (
        '[IMPORTANT: The user invoked the "llm-wiki" skill: private-skill-header]\n'
    )
    tail = "\n[Skill directory resolved]\nprivate-concrete-request-tail"
    expanded_message = header + ("x" * (20_294 - len(header) - len(tail))) + tail
    assert len(expanded_message) == 20_294
    captured: dict[str, Any] = {}

    def preflight(_action: str, arguments: dict[str, Any]) -> dict[str, Any]:
        captured.update(arguments)
        return _preflight()

    monkeypatch.setattr(plugin, "_run_rpc", preflight)
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="skill-turn",
        user_message=expanded_message,
    )
    assert injected is not None
    bounded_query = captured["query"]
    assert len(bounded_query) == plugin.MAX_QUERY_CHARS
    assert bounded_query.startswith(header)
    assert bounded_query.endswith(tail)
    assert plugin._PREFLIGHT_QUERY_OMISSION in bounded_query
    assert "reason=preflight_query_middle_omitted" in caplog.text
    assert "private-skill-header" not in caplog.text
    assert "private-concrete-request-tail" not in caplog.text

    request = {
        "messages": [
            {
                "role": "user",
                "content": f"{expanded_message}\n\n{injected['context']}",
            }
        ]
    }
    provider_calls: list[object] = []
    result = plugin.on_llm_execution(
        request=request,
        next_call=lambda value: provider_calls.append(value) or "provider-response",
        session_id="session",
        task_id="task",
        turn_id="skill-turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert result == "provider-response"
    assert provider_calls == [request]


def test_failed_preflight_returns_generic_zero_usage_without_provider(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(
        plugin,
        "_run_rpc",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            RuntimeError("sensitive backend detail")
        ),
    )
    assert (
        plugin.on_pre_llm_call(
            session_id="session",
            task_id="task",
            turn_id="turn",
            user_message="Use protected context.",
        )
        is None
    )
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request={},
        next_call=lambda value: provider_calls.append(value),
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert provider_calls == []
    assert result.choices[0].message.content == plugin.REQUIRED_PREFLIGHT_FAILURE
    assert result.usage.total_tokens == 0
    assert "sensitive backend detail" not in result.choices[0].message.content
    assert "reason=preflight_rpc_unavailable" in caplog.text
    assert "sensitive backend detail" not in caplog.text


def test_attestation_is_bound_to_exact_session_task_and_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn-a",
        user_message="Recall this.",
    )
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request={},
        next_call=lambda value: provider_calls.append(value),
        session_id="session",
        task_id="task",
        turn_id="turn-b",
        api_mode="chat_completions",
        model="local-model",
    )

    assert provider_calls == []
    assert result.usage.total_tokens == 0


def test_execution_blocks_when_host_drops_current_turn_context(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn",
        user_message="Recall this.",
    )
    assert injected is not None
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request={
            "messages": [
                {
                    "role": "user",
                    "content": "nonce was dropped: private-request-detail",
                }
            ]
        },
        next_call=lambda value: provider_calls.append(value),
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert provider_calls == []
    assert result.usage.total_tokens == 0
    assert "reason=protected_context_missing" in caplog.text
    assert "private-request-detail" not in caplog.text


def test_long_tool_turn_keeps_valid_current_user_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression: tool schemas/history must not exhaust the nonce scan."""

    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="long-tool-turn",
        user_message="Complete the multi-step task.",
    )
    assert injected is not None

    messages: list[dict[str, Any]] = [
        {
            "role": "user",
            "content": f"Complete the multi-step task.\n\n{injected['context']}",
        }
    ]
    for index in range(150):
        messages.extend(
            (
                {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": f"call-{index}",
                            "type": "function",
                            "function": {
                                "name": "inspect_workspace",
                                "arguments": '{"path":"src"}',
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": f"call-{index}",
                    "content": f"tool result {index}: " + ("x" * 200),
                },
            )
        )
    tools = [
        {
            "type": "function",
            "function": {
                "name": f"workspace_tool_{index}",
                "description": "Inspect a workspace object. " + ("d" * 300),
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "p" * 100},
                        "options": {
                            "type": "object",
                            "properties": {
                                "recursive": {"type": "boolean"},
                                "limit": {"type": "integer"},
                            },
                        },
                    },
                },
            },
        }
        for index in range(35)
    ]
    request = {"model": "local-model", "messages": messages, "tools": tools}
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request=request,
        next_call=lambda value: provider_calls.append(value) or "provider-response",
        session_id="session",
        task_id="task",
        turn_id="long-tool-turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert result == "provider-response"
    assert provider_calls == [request]


def test_execution_ignores_nonce_copies_outside_user_message(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn",
        user_message="Use protected context.",
    )
    assert injected is not None
    request = {
        "messages": [{"role": "user", "content": "unprotected user message"}],
        "tools": [
            {
                "type": "function",
                "function": {
                    "name": "untrusted_tool",
                    "description": injected["context"],
                    "parameters": {"type": "object"},
                },
            }
        ],
        "metadata": {"copied_context": injected["context"]},
    }
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request=request,
        next_call=lambda value: provider_calls.append(value),
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert provider_calls == []
    assert result.usage.total_tokens == 0


def test_execution_rejects_bare_nonce_without_protected_envelope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn",
        user_message="Use protected context.",
    )
    assert injected is not None
    nonce_line = next(
        line
        for line in injected["context"].splitlines()
        if line.startswith("ECHO_VEIL_HERMES_TURN_NONCE=")
    )
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request={"messages": [{"role": "user", "content": nonce_line}]},
        next_call=lambda value: provider_calls.append(value),
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert provider_calls == []
    assert result.usage.total_tokens == 0


@pytest.mark.parametrize(
    ("api_mode", "provider_request"),
    (
        (
            "codex_responses",
            {
                "input": [
                    {
                        "role": "user",
                        "content": [{"type": "input_text", "text": "{context}"}],
                    }
                ]
            },
        ),
        (
            "anthropic_messages",
            {
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": "{context}"}],
                    }
                ]
            },
        ),
        (
            "bedrock_converse",
            {"messages": [{"role": "user", "content": [{"text": "{context}"}]}]},
        ),
    ),
)
def test_execution_accepts_supported_provider_user_text_shapes(
    monkeypatch: pytest.MonkeyPatch,
    api_mode: str,
    provider_request: dict[str, Any],
) -> None:
    monkeypatch.setattr(plugin, "_run_rpc", lambda *_args, **_kwargs: _preflight())
    injected = plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn",
        user_message="Use protected context.",
    )
    assert injected is not None
    container_name = "input" if api_mode == "codex_responses" else "messages"
    provider_request[container_name][0]["content"][0]["text"] = injected["context"]
    provider_calls: list[object] = []

    result = plugin.on_llm_execution(
        request=provider_request,
        next_call=lambda value: provider_calls.append(value) or "provider-response",
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode=api_mode,
        model="local-model",
    )

    assert result == "provider-response"
    assert provider_calls == [provider_request]


def test_deny_only_outage_control_never_reaches_child_or_provider(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE", "1")
    rpc_calls: list[object] = []
    monkeypatch.setattr(
        plugin,
        "_run_rpc",
        lambda *args, **kwargs: rpc_calls.append((args, kwargs)) or _preflight(),
    )
    assert "ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE" not in plugin._child_environment()

    plugin.on_pre_llm_call(
        session_id="session",
        task_id="task",
        turn_id="turn",
        user_message="Recall this.",
    )
    provider_calls: list[object] = []
    result = plugin.on_llm_execution(
        request={},
        next_call=lambda value: provider_calls.append(value),
        session_id="session",
        task_id="task",
        turn_id="turn",
        api_mode="chat_completions",
        model="local-model",
    )

    assert rpc_calls == []
    assert provider_calls == []
    assert result.usage.total_tokens == 0


def test_oversized_context_never_creates_attestation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        plugin,
        "_run_rpc",
        lambda *_args, **_kwargs: _preflight(
            "ECHO VEIL REQUIRED MEMORY PREFLIGHT\n" + ("x" * plugin.MAX_CONTEXT_CHARS)
        ),
    )

    assert (
        plugin.on_pre_llm_call(
            session_id="session",
            task_id="task",
            turn_id="turn",
            user_message="Recall this.",
        )
        is None
    )


@pytest.mark.parametrize(
    ("mode", "field"),
    (
        ("chat_completions", "choices"),
        ("bedrock_converse", "choices"),
        ("anthropic_messages", "content"),
        ("codex_responses", "output"),
    ),
)
def test_blocked_response_has_valid_host_shape_and_zero_usage(
    mode: str,
    field: str,
) -> None:
    response = plugin._blocked_response(mode, "model")

    assert getattr(response, field)
    assert response.usage.total_tokens == 0
    if mode == "anthropic_messages":
        assert response.content[0].text == plugin.REQUIRED_PREFLIGHT_FAILURE
    elif mode == "codex_responses":
        assert response.output_text == plugin.REQUIRED_PREFLIGHT_FAILURE
    else:
        assert response.choices[0].message.content == plugin.REQUIRED_PREFLIGHT_FAILURE


def test_rpc_uses_fixed_command_shell_false_and_allowlisted_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    def fake_run(command: list[str], **kwargs: Any) -> SimpleNamespace:
        captured["command"] = command
        captured.update(kwargs)
        return SimpleNamespace(
            returncode=0,
            stdout=(
                b'{"preflight_ready":true,"memory_authority":"echo-veil",'
                b'"host":"hermes","profile":"echo-universal-qwen3-v1",'
                b'"query_source":"current_user_prompt","semantic":true,'
                b'"context":"ECHO VEIL REQUIRED MEMORY PREFLIGHT\\\\nready"}'
            ),
        )

    monkeypatch.setattr(plugin.subprocess, "run", fake_run)
    value = plugin._run_rpc("preflight", {"query": "hello"})

    assert captured["command"][0] == "echo-veil-agent"
    assert captured["command"][-1] == "rpc"
    assert captured["shell"] is False
    assert captured["check"] is False
    assert captured["env"]["ECHO_VEIL_CALLER"] == "hermes"
    assert "ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE" not in captured["env"]
    assert value["host"] == "hermes"


def _shielded_config() -> dict[str, Any]:
    return {
        "memory": {
            "memory_enabled": False,
            "user_profile_enabled": False,
        },
        "plugins": {"enabled": ["echo-veil-shield"]},
        "providers": {
            plugin.SHIELDED_LOCAL_PROVIDER: {
                "api": "http://127.0.0.1:11434/v1",
            }
        },
        "mcp_servers": {
            "echo-veil": {
                "command": "/reviewed/echo-veil-agent",
                "args": [
                    "--profile",
                    plugin.CANONICAL_PROFILE,
                    "--scope",
                    plugin.CANONICAL_SCOPE,
                    "--caller",
                    "hermes",
                    "mcp",
                ],
                "enabled": True,
            }
        },
    }


def test_shielded_prompt_requires_exact_launcher_nonce(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = "a" * 32
    monkeypatch.setenv(plugin.SHIELDED_RUN_NONCE_ENV, nonce)

    assert (
        plugin._read_shielded_prompt(
            BytesIO(f"{plugin.SHIELDED_RUN_MARKER}{nonce}\nprotected".encode())
        )
        == f"{plugin.SHIELDED_RUN_MARKER}{nonce}\nprotected"
    )
    with pytest.raises(ValueError, match="binding"):
        plugin._read_shielded_prompt(BytesIO(b"unbound"))


def test_shielded_config_rejects_native_or_competing_memory() -> None:
    config = _shielded_config()
    plugin._validate_shielded_config(config)

    config["memory"]["memory_enabled"] = True
    with pytest.raises(ValueError, match="native memory"):
        plugin._validate_shielded_config(config)

    config = _shielded_config()
    config["plugins"]["enabled"].append("other-plugin")
    with pytest.raises(ValueError, match="exclusive"):
        plugin._validate_shielded_config(config)

    config = _shielded_config()
    config["providers"][plugin.SHIELDED_LOCAL_PROVIDER]["api"] = (
        "https://provider.example/v1"
    )
    with pytest.raises(ValueError, match="not local"):
        plugin._validate_shielded_config(config)


def test_shielded_command_runs_one_echo_only_turn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    nonce = "b" * 32
    monkeypatch.setenv(plugin.SHIELDED_RUN_NONCE_ENV, nonce)
    monkeypatch.setattr(
        plugin.sys,
        "stdin",
        SimpleNamespace(
            buffer=BytesIO(f"{plugin.SHIELDED_RUN_MARKER}{nonce}\nprotected".encode())
        ),
    )
    observed: dict[str, Any] = {}
    hermes_package = ModuleType("hermes_cli")
    hermes_package.__path__ = []  # type: ignore[attr-defined]
    config_module = ModuleType("hermes_cli.config")
    config_module.read_raw_config = _shielded_config  # type: ignore[attr-defined]
    oneshot_module = ModuleType("hermes_cli.oneshot")

    def run_oneshot(prompt: str, **kwargs: Any) -> int:
        observed["prompt"] = prompt
        observed.update(kwargs)
        return 0

    oneshot_module.run_oneshot = run_oneshot  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "hermes_cli", hermes_package)
    monkeypatch.setitem(sys.modules, "hermes_cli.config", config_module)
    monkeypatch.setitem(sys.modules, "hermes_cli.oneshot", oneshot_module)

    result = plugin._run_shielded_command(
        SimpleNamespace(
            model="qwen3.6:35b-mlx",
            provider=plugin.SHIELDED_LOCAL_PROVIDER,
        )
    )

    assert result == 0
    assert observed["prompt"].startswith(plugin.SHIELDED_RUN_MARKER)
    assert observed["model"] == "qwen3.6:35b-mlx"
    assert observed["provider"] == plugin.SHIELDED_LOCAL_PROVIDER
    assert observed["toolsets"] == "echo-veil"


def test_register_requires_and_wires_execution_middleware_and_cli_gate() -> None:
    hooks: list[tuple[str, object]] = []
    middleware: list[tuple[str, object]] = []
    commands: list[dict[str, object]] = []
    context = SimpleNamespace(
        register_hook=lambda name, callback: hooks.append((name, callback)),
        register_middleware=lambda name, callback: middleware.append((name, callback)),
        register_cli_command=lambda **kwargs: commands.append(kwargs),
    )

    plugin.register(context)

    assert ("pre_llm_call", plugin.on_pre_llm_call) in hooks
    assert ("llm_execution", plugin.on_llm_execution) in middleware
    assert commands == [
        {
            "name": plugin.SHIELDED_RUN_COMMAND,
            "help": "Run one Echo Veil shielded, memory-only Hermes turn",
            "setup_fn": plugin._setup_shielded_run_parser,
            "handler_fn": plugin._run_shielded_command,
            "description": (
                "Requires an external Echo preflight, isolated Hermes home, "
                "disabled native memory, and the Echo-only MCP toolset."
            ),
        }
    ]


def test_register_fails_when_host_cannot_create_shielded_command() -> None:
    context = SimpleNamespace(
        register_hook=lambda *_args: None,
        register_middleware=lambda *_args: None,
    )

    with pytest.raises(RuntimeError, match="lifecycle APIs"):
        plugin.register(context)
