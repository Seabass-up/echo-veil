from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
import re
from pathlib import Path
from typing import Any, cast

import pytest

from echo_veil.agent_cli import McpServer
from echo_veil.agent_memory import AgentMemory


ROOT = Path(__file__).parents[1]
VERSION = "0.8.0"
HOSTS = (
    "algo-cli",
    "aip",
    "openclaw",
    "hermes",
    "codex",
    "claude-code",
    "pi",
    "opencode",
    "droid",
    "goose",
    "grok-build",
    "mercury",
)
FULL_TOOL_HOSTS = (
    "openclaw",
    "hermes",
    "codex",
    "claude-code",
    "pi",
    "opencode",
    "droid",
    "goose",
    "grok-build",
)

HOST_ENFORCEMENT_TIERS = {
    "algo-cli": "Hard pre-model gate",
    "aip": "Hard runtime pre-provider gate",
    "openclaw": "Hard OpenClaw-runtime pre-model gate",
    "hermes": "Hard shielded memory-only gate",
    "codex": "Hard isolated gate",
    "claude-code": "Hard root/Agent-spawn gate",
    "pi": "Hard isolated pre-provider gate",
    "opencode": "Hard root/Task-spawn gate",
    "droid": "Hard shielded headless gate",
    "goose": "Hard shielded headless gate",
    "grok-build": "Protected recall and injected context",
    "mercury": "Blocked for singular authority",
}

MEMORY_SKILL_REQUIRED_TEXT = (
    "primary mutable agent-memory store",
    "echo_veil_doctor",
    "echo_veil_recall",
    "echo_veil_context",
    "ranking_ambiguous=true",
    "competing_memory_detected=true",
    "degraded=true",
    "Long-Term",
    "Contextual Logic",
    "plaintext fallback",
    "lifecycle-neutral",
)


def _json(path: str) -> dict[str, object]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value)


def test_plugin_versions_and_mcp_profiles_are_aligned() -> None:
    codex_marketplace = _json(".agents/plugins/marketplace.json")
    claude_marketplace = _json(".claude-plugin/marketplace.json")
    codex = _mapping(_mapping(_json(".mcp.json")["mcpServers"])["echo-veil"])
    claude = _mapping(
        _mapping(_json("integrations/claude-code/.mcp.json")["mcpServers"])["echo-veil"]
    )
    grok = _mapping(
        _mapping(_json("integrations/grok/.mcp.json")["mcpServers"])["echo-veil"]
    )
    droid = _mapping(
        _mapping(_json("integrations/droid/.factory/mcp.json")["mcpServers"])[
            "echo-veil"
        ]
    )
    opencode = _mapping(
        _mapping(_json("integrations/opencode/opencode.json")["mcp"])["echo_veil"]
    )
    opencode_permissions = _mapping(
        _json("integrations/opencode/opencode.json")["permission"]
    )
    openclaw_contracts = _mapping(
        _json("integrations/openclaw/openclaw.plugin.json")["contracts"]
    )
    pi_resources = _mapping(_json("integrations/pi/package.json")["pi"])

    assert codex["env"]["ECHO_VEIL_PROFILE"] == "echo-universal-qwen3-v1"
    assert claude["env"]["ECHO_VEIL_PROFILE"] == "echo-universal-qwen3-v1"
    assert codex["command"] == "echo-veil-agent"
    assert codex["args"] == ["mcp"]
    assert claude["command"] == "echo-veil-agent"
    assert claude["args"] == ["mcp"]
    for config, caller in (
        (codex, "codex"),
        (claude, "claude-code"),
        (grok, "grok-build"),
    ):
        assert config["env"]["ECHO_VEIL_SCOPE"] == "local-user"
        assert config["env"]["ECHO_VEIL_CALLER"] == caller
        assert config["env"]["ECHO_VEIL_EMBEDDER"] == "ollama"
        assert config["env"]["ECHO_VEIL_EMBEDDING_MODEL"] == ("qwen3-embedding:latest")
        assert config["env"]["ECHO_VEIL_EMBEDDING_DIMENSION"] == "1024"
        assert config["env"]["ECHO_VEIL_AVAILABILITY_LAYER"] == "true"
        assert "ECHO_VEIL_OPERATOR_TOOLS" not in config["env"]
    assert droid["args"] == [
        "--profile",
        "echo-universal-qwen3-v1",
        "--scope",
        "local-user",
        "--caller",
        "droid",
        "--embedder",
        "ollama",
        "--embedding-model",
        "qwen3-embedding:latest",
        "--embedding-dimension",
        "1024",
        "--availability-layer",
        "mcp",
    ]
    assert opencode["command"] == [
        "echo-veil-agent",
        "--profile",
        "echo-universal-qwen3-v1",
        "--scope",
        "local-user",
        "--caller",
        "opencode",
        "--embedder",
        "ollama",
        "--embedding-model",
        "qwen3-embedding:latest",
        "--embedding-dimension",
        "1024",
        "--availability-layer",
        "mcp",
    ]
    assert "echo_veil_promote" in openclaw_contracts["tools"]
    assert "echo_veil_refresh_live" in openclaw_contracts["tools"]
    assert "echo_veil_context" in openclaw_contracts["tools"]
    assert "echo_veil_list" in openclaw_contracts["tools"]
    assert pi_resources["extensions"] == ["./extensions"]
    assert pi_resources["skills"] == ["./skills"]
    assert opencode_permissions["echo-veil_echo_veil_promote"] == "ask"
    assert opencode_permissions["echo-veil_echo_veil_refresh_live"] == "ask"
    assert opencode_permissions["echo-veil_echo_veil_recall"] == "ask"
    assert opencode_permissions["echo-veil_echo_veil_context"] == "ask"
    assert opencode_permissions["echo-veil_echo_veil_reindex"] == "ask"
    assert "--operator-tools" not in droid["args"]
    assert "--operator-tools" not in opencode["command"]

    for path in (
        ".codex-plugin/plugin.json",
        "integrations/claude-code/.claude-plugin/plugin.json",
        "integrations/grok/plugin.json",
        "integrations/openclaw/openclaw.plugin.json",
        "integrations/openclaw/package.json",
        "integrations/opencode/package.json",
        "integrations/opencode/package-lock.json",
        "integrations/pi/package.json",
    ):
        assert _json(path)["version"] == VERSION
    codex_plugins = codex_marketplace["plugins"]
    assert isinstance(codex_plugins, list) and len(codex_plugins) == 1
    codex_source = _mapping(_mapping(codex_plugins[0])["source"])
    assert codex_source == {"source": "local", "path": "."}
    claude_plugins = claude_marketplace["plugins"]
    assert isinstance(claude_plugins, list) and len(claude_plugins) == 1
    claude_entry = _mapping(claude_plugins[0])
    assert claude_entry["source"] == "./integrations/claude-code"
    assert claude_entry["version"] == VERSION
    grok_marketplace = _json(".grok-plugin/marketplace.json")
    grok_plugins = grok_marketplace["plugins"]
    assert isinstance(grok_plugins, list) and len(grok_plugins) == 1
    grok_entry = _mapping(grok_plugins[0])
    assert grok_entry["source"] == "./integrations/grok"
    assert grok_entry["version"] == VERSION


def test_droid_plugin_packages_root_and_task_contract_without_timeout_bypass() -> None:
    marketplace = _json(".factory-plugin/marketplace.json")
    project_hooks = _json("integrations/droid/.factory/hooks.json")
    plugin_hooks = _json("integrations/droid/hooks/hooks.json")
    plugin_manifest = _json("integrations/droid/.factory-plugin/plugin.json")
    project_wrapper = (
        ROOT / "integrations/droid/.factory/hooks/echo-veil-preflight.sh"
    ).read_text(encoding="utf-8")
    plugin_wrapper = (
        ROOT / "integrations/droid/hooks/echo-veil-preflight.sh"
    ).read_text(encoding="utf-8")

    assert plugin_manifest["version"] == VERSION
    assert marketplace["name"] == "echo-veil"
    assert marketplace["plugins"] == [
        {
            "name": "echo-veil",
            "description": (
                "Shielded four-layer memory tools, skill, and Droid hook definitions."
            ),
            "source": "./integrations/droid",
            "category": "security",
        }
    ]
    assert project_wrapper == plugin_wrapper
    assert "ECHO_VEIL_PREFLIGHT_COMMAND" in project_wrapper
    assert '"${HOME}/.local/bin/echo-veil-preflight-hook"' in project_wrapper
    assert 'case "$preflight_command" in\n  /*)' in project_wrapper
    assert '"$preflight_command" --host droid --hook-mode "$mode"' in project_wrapper
    assert "eval " not in project_wrapper

    for manifest, root_marker in (
        (project_hooks, "$FACTORY_PROJECT_DIR"),
        (plugin_hooks, "${DROID_PLUGIN_ROOT}"),
    ):
        hooks = _mapping(manifest["hooks"] if "hooks" in manifest else manifest)
        root_groups = hooks["UserPromptSubmit"]
        task_groups = hooks["PreToolUse"]
        assert isinstance(root_groups, list) and len(root_groups) == 1
        assert isinstance(task_groups, list) and len(task_groups) == 1
        root_handler = _mapping(_mapping(root_groups[0])["hooks"][0])
        task_group = _mapping(task_groups[0])
        task_handler = _mapping(task_group["hooks"][0])
        assert task_group["matcher"] == "Task"
        assert root_marker in root_handler["command"]
        assert re.search(
            r'echo-veil-preflight\.sh"? prompt$',
            root_handler["command"],
        )
        assert re.search(
            r'echo-veil-preflight\.sh"? agent$',
            task_handler["command"],
        )
        assert "timeout" not in root_handler
        assert "timeout" not in task_handler


def test_skill_capable_hosts_ship_one_fail_closed_memory_ritual() -> None:
    codex_skill = (ROOT / "skills/echo-veil-memory/SKILL.md").read_text(
        encoding="utf-8"
    )
    claude_skill = (
        ROOT / "integrations/claude-code/skills/echo-veil-memory/SKILL.md"
    ).read_text(encoding="utf-8")
    hermes_skill = (
        ROOT / "integrations/hermes/skills/echo-veil-memory/SKILL.md"
    ).read_text(encoding="utf-8")
    pi_skill = (ROOT / "integrations/pi/skills/echo-veil-memory/SKILL.md").read_text(
        encoding="utf-8"
    )
    opencode_skill = (
        ROOT / "integrations/opencode/.opencode/skills/echo-veil-memory/SKILL.md"
    ).read_text(encoding="utf-8")
    droid_skill = (
        ROOT / "integrations/droid/.factory/skills/echo-veil-memory/SKILL.md"
    ).read_text(encoding="utf-8")
    grok_skill = (
        ROOT / "integrations/grok/skills/echo-veil-memory/SKILL.md"
    ).read_text(encoding="utf-8")
    openai_metadata = (ROOT / "skills/echo-veil-memory/agents/openai.yaml").read_text(
        encoding="utf-8"
    )
    codex_manifest = _json(".codex-plugin/plugin.json")
    codex_hooks = _json("hooks/hooks.json")
    claude_hooks = _json("integrations/claude-code/hooks/hooks.json")
    grok_hooks = _json("integrations/grok/hooks/hooks.json")

    assert codex_skill == claude_skill
    assert codex_skill == hermes_skill
    assert codex_skill == pi_skill
    assert codex_skill == opencode_skill
    assert codex_skill == droid_skill
    assert codex_skill == grok_skill
    assert codex_skill.startswith("---\nname: echo-veil-memory\n")
    for required in MEMORY_SKILL_REQUIRED_TEXT:
        assert required in codex_skill
    assert "allow_implicit_invocation: true" in openai_metadata
    assert "$echo-veil-memory" in openai_metadata
    assert codex_manifest["skills"] == "./skills/"
    assert codex_manifest["hooks"] == "./hooks/hooks.json"
    assert len(_mapping(codex_manifest["interface"])["defaultPrompt"]) <= 3
    codex_prompt_hooks = _mapping(codex_hooks["hooks"])["UserPromptSubmit"]
    codex_agent_hooks = _mapping(codex_hooks["hooks"])["PreToolUse"]
    claude_prompt_hooks = _mapping(claude_hooks["hooks"])["UserPromptSubmit"]
    claude_expansion_hooks = _mapping(claude_hooks["hooks"])["UserPromptExpansion"]
    grok_prompt_hooks = _mapping(grok_hooks["hooks"])["UserPromptSubmit"]
    for hooks, caller in (
        (codex_prompt_hooks, "codex"),
        (claude_prompt_hooks, "claude-code"),
        (claude_expansion_hooks, "claude-code"),
        (grok_prompt_hooks, "grok-build"),
    ):
        assert isinstance(hooks, list) and len(hooks) == 1
        handlers = _mapping(hooks[0])["hooks"]
        assert isinstance(handlers, list) and len(handlers) == 1
        handler = _mapping(handlers[0])
        assert handler["type"] == "command"
        assert "echo-veil-preflight-hook" in handler["command"]
        assert f"--host {caller}" in handler["command"]
        assert "--hook-mode prompt" in handler["command"]
        assert handler["timeout"] == 30
    for hooks, caller, matcher in (
        (
            codex_agent_hooks,
            "codex",
            r"^(Agent|SpawnAgent|spawn_agent|collaboration\.spawn_agent)$",
        ),
        (
            _mapping(claude_hooks["hooks"])["PreToolUse"],
            "claude-code",
            "Agent",
        ),
        (
            _mapping(grok_hooks["hooks"])["PreToolUse"],
            "grok-build",
            "spawn_subagent|Task",
        ),
    ):
        assert isinstance(hooks, list) and len(hooks) == 1
        hook_group = _mapping(hooks[0])
        assert hook_group["matcher"] == matcher
        handlers = hook_group["hooks"]
        assert isinstance(handlers, list) and len(handlers) == 1
        handler = _mapping(handlers[0])
        assert handler["type"] == "command"
        assert "echo-veil-preflight-hook" in handler["command"]
        assert f"--host {caller}" in handler["command"]
        assert "--hook-mode agent" in handler["command"]
        assert handler["timeout"] == 30
    assert (
        _mapping(_mapping(codex_prompt_hooks[0])["hooks"][0])["command"]
        == "echo-veil-preflight-hook --host codex --hook-mode prompt"
    )
    assert (
        _mapping(_mapping(claude_prompt_hooks[0])["hooks"][0])["command"]
        == "echo-veil-preflight-hook --host claude-code --hook-mode prompt"
    )
    assert (
        _mapping(_mapping(grok_prompt_hooks[0])["hooks"][0])["command"]
        == "echo-veil-preflight-hook --host grok-build --hook-mode prompt"
    )


def test_text_configs_cover_every_host_and_preserve_security_boundary() -> None:
    integration_readme = (ROOT / "integrations/README.md").read_text(encoding="utf-8")
    for host in HOSTS:
        assert re.search(rf"\b{re.escape(host)}\b", integration_readme, re.IGNORECASE)
    for host, tier in HOST_ENFORCEMENT_TIERS.items():
        host_label_pattern = re.escape(host).replace(r"\-", r"[- ]")
        assert re.search(
            rf"\|\s*{host_label_pattern}\s*\|[^\n]*\*\*{re.escape(tier)}\*\*",
            integration_readme,
            re.IGNORECASE,
        )
    assert re.search(
        r"Algo CLI required mode,\s+OpenClaw's pinned runtime,\s+"
        r"receipt-bound isolated Pi,\s+and a "
        r"loaded Hermes\s+shield plugin currently own broad tested "
        r"model-turn stop",
        integration_readme,
    )
    assert re.search(
        r"host has no required-plugin\s+startup policy",
        integration_readme,
    )
    assert "normal Goose recipe remains policy-driven" in integration_readme
    assert "Droid 0.180.0 `exec` bypasses native prompt hooks" in integration_readme

    hermes = (ROOT / "integrations/hermes/config.yaml").read_text(encoding="utf-8")
    hermes_plugin = (ROOT / "integrations/hermes/plugin/__init__.py").read_text(
        encoding="utf-8"
    )
    hermes_manifest = (ROOT / "integrations/hermes/plugin/plugin.yaml").read_text(
        encoding="utf-8"
    )
    hermes_readme = (ROOT / "integrations/hermes/README.md").read_text(encoding="utf-8")
    goose = (ROOT / "integrations/goose/echo-veil.yaml").read_text(encoding="utf-8")
    goose_readme = (ROOT / "integrations/goose/README.md").read_text(encoding="utf-8")
    mercury = (ROOT / "integrations/mercury/SKILL.md").read_text(encoding="utf-8")
    opencode_plugin = (
        ROOT / "integrations/opencode/.opencode/plugins/echo-veil-shield.js"
    ).read_text(encoding="utf-8")
    for text, profile, caller in (
        (hermes, "echo-universal-qwen3-v1", "hermes"),
        (goose, "echo-universal-qwen3-v1", "goose"),
    ):
        assert (
            f'args: ["--profile", "{profile}", "--scope", "local-user", '
            f'"--caller", "{caller}", "--embedder", "ollama"'
        ) in text
        assert '"qwen3-embedding:latest"' in text
        assert '"--availability-layer"' in text
        assert "--operator-tools" not in text
    assert "ranking_ambiguous=true" in goose
    assert "competing_memory_detected=true" in goose
    assert "Never invent a resolution" in goose
    assert "echo_veil_promote" in hermes
    assert "echo_veil_refresh_live" in hermes
    assert "echo_veil_promote" in goose
    assert "echo_veil_refresh_live" in goose
    assert "echo_veil_context" in hermes
    assert "echo_veil_context" in goose
    assert "echo_veil_list" in hermes
    assert "echo_veil_list" in goose
    assert "echo_veil_reindex" in hermes
    assert f'version: "{VERSION}"' in hermes_manifest
    assert 'register_hook("pre_llm_call"' in hermes_plugin
    assert 'register_middleware("llm_execution"' in hermes_plugin
    assert "shell=False" in hermes_plugin
    assert "ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE" in hermes_plugin
    assert "ECHO_VEIL_HERMES_TURN_NONCE" in hermes_plugin
    assert "echo-veil-run" in hermes_plugin
    assert "MAX_CONTEXT_CHARS = 9_000" in hermes_plugin
    assert "echo-veil-shielded-run hermes" in hermes_readme
    assert "digest-bound" in hermes_readme
    assert "Echo MCP toolset" in hermes_readme
    assert "ordinary plugin mode" in hermes_readme
    assert "echo_veil_reindex only after explicit confirmation" in goose
    assert "Call echo_veil_doctor before the first memory-dependent operation" in goose
    assert (
        "For a substantive task whose answer may depend on prior state, call" in goose
    )
    assert "primary mutable agent-memory store" in goose
    assert "host plaintext fallback" in goose
    assert "not independently query-scored" in goose
    assert "never as\n" in goose
    assert "semantic or authoritative recall" in goose
    assert "do not launch Goose with\n  --no-profile" in goose
    assert "suppresses recipe-defined extensions" in goose
    assert 'query "Echo Veil singular memory authority current state"' in goose
    assert "top_k 2" in goose
    assert "inferential recall disabled" in goose
    assert "echo-veil-shielded-run goose" in goose_readme
    assert "--no-profile" in goose_readme
    assert "--no-session" in goose_readme
    assert "normal recipe remains policy-driven" in goose_readme
    assert "allowed-tools:\n  - run_command" in mercury
    assert "A shell command string is\nnot a safe payload transport" in mercury
    assert "must not send memory topics, payloads, queries" in mercury
    assert "full remember, recall, and forget operations are unavailable" in mercury
    assert "SECOND_BRAIN_ENABLED=false" in mercury
    assert "not an all-memory-off switch" in mercury
    assert "incompatible with singular-authority mode" in mercury
    assert "must not mutate Mercury's memory configuration" in mercury
    assert "Short-Term, Long-Term, and\nEpisodic" in mercury
    assert "mercury skills install --from ./integrations/mercury/SKILL.md" in mercury
    assert "echo-veil-agent rpc" not in mercury
    assert "echo-veil-agent mcp" not in mercury
    assert '"chat.message"' in opencode_plugin
    assert '"chat.params"' in opencode_plugin
    assert '"tool.execute.before"' in opencode_plugin
    assert '"experimental.compaction.autocontinue"' in opencode_plugin
    assert "subagent_task" in opencode_plugin
    assert "shell: false" in opencode_plugin
    assert "ECHO_VEIL_PROTECTED_OPENCODE_CONTEXT_BEGIN" in opencode_plugin
    pi_extension = (ROOT / "integrations/pi/extensions/index.ts").read_text(
        encoding="utf-8"
    )
    pi_preflight = (ROOT / "integrations/pi/src/preflight.ts").read_text(
        encoding="utf-8"
    )
    for required in (
        'pi.on("input"',
        'pi.on("before_agent_start"',
        'pi.on("agent_start"',
        'pi.on("tool_call"',
        "ctx.abort()",
        "REQUIRED_PREFLIGHT_FAILURE",
    ):
        assert required in pi_extension
    for required in (
        'this.rpc("preflight_v2"',
        "ritual_satisfied",
        "MAX_PREFLIGHT_ESTIMATED_TOKENS",
        "payload_included",
        "untrusted_memory_evidence",
        "ranking_ambiguous",
        "competing_memory_detected",
    ):
        assert required in pi_preflight
    aip = (ROOT / "integrations/aip/README.md").read_text(encoding="utf-8")
    assert "no plaintext" in aip.lower()
    assert "`memory.recent`" in aip
    assert "lifecycle-neutral" in aip
    assert "canonical user data root" in aip
    assert "memory universe" in aip
    assert "explicit `shared` domain" in aip


def _tool_call(
    server: McpServer,
    request_id: int,
    name: str,
    arguments: dict[str, object],
) -> dict[str, Any]:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None
    result = _mapping(response["result"])
    assert result["isError"] is False, result
    return _mapping(result["structuredContent"])


@pytest.mark.parametrize("host", FULL_TOOL_HOSTS)
def test_every_full_host_conforms_to_four_layer_caller_bound_contract(
    tmp_path: Path,
    host: str,
) -> None:
    marker = f"caller:{host}"
    with AgentMemory(tmp_path / host) as memory:
        server = McpServer(memory, caller=host)
        listed = server.handle(
            {"jsonrpc": "2.0", "id": 0, "method": "tools/list", "params": {}}
        )
        assert listed is not None
        tool_names = {tool["name"] for tool in listed["result"]["tools"]}
        assert len(tool_names) == 9
        assert tool_names.isdisjoint({"echo_veil_rotate_key", "echo_veil_retire_key"})
        live = _tool_call(
            server,
            1,
            "echo_veil_remember",
            {
                "topic": f"{host} active verification",
                "payload": "The cross-host verification is running.",
                "layer": "live",
            },
        )
        refreshed = _tool_call(
            server,
            2,
            "echo_veil_refresh_live",
            {
                "vine_id": live["vine_id"],
                "payload": "The cross-host verification passed.",
                "provenance": ["receipt:adapter-conformance"],
            },
        )
        short = _tool_call(
            server,
            3,
            "echo_veil_promote",
            {
                "vine_id": refreshed["vine_id"],
                "target_layer": "short_term",
                "reason": "The verified result remains useful across this session.",
                "provenance": ["task:verified"],
            },
        )
        durable = _tool_call(
            server,
            4,
            "echo_veil_promote",
            {
                "vine_id": short["vine_id"],
                "target_layer": "long_term",
                "reason": "The conformance rule was explicitly reviewed.",
                "provenance": ["review:explicit"],
            },
        )
        evidence = _tool_call(
            server,
            5,
            "echo_veil_remember",
            {
                "topic": f"{host} conformance evidence",
                "payload": "The caller-bound four-layer adapter contract passed.",
                "provenance": ["receipt:four-layer-gate"],
            },
        )
        logic = _tool_call(
            server,
            6,
            "echo_veil_remember",
            {
                "topic": f"{host} conformance decision",
                "payload": "Use the caller-bound adapter because its protected gate passed.",
                "layer": "contextual_logic",
                "provenance": ["decision:adapter-conformance"],
                "promotion_reason": "Two protected records support this decision.",
                "logic_kind": "decision",
                "related_ids": [durable["vine_id"], evidence["vine_id"]],
            },
        )
        recalled = _tool_call(
            server,
            7,
            "echo_veil_recall",
            {
                "query": (
                    f"{host} conformance decision caller-bound protected gate passed"
                ),
                "layers": ["contextual_logic"],
                "top_k": 2,
            },
        )
        context = _tool_call(
            server,
            8,
            "echo_veil_context",
            {
                "query": (
                    f"{host} conformance decision caller-bound protected gate passed"
                ),
                "max_depth": 1,
                "max_records": 4,
            },
        )
        inventory = _tool_call(
            server,
            9,
            "echo_veil_list",
            {
                "limit": 10,
                "layers": ["long_term", "contextual_logic"],
                "newest_first": True,
            },
        )
        doctor = _tool_call(server, 10, "echo_veil_doctor", {})

    for record in (live, refreshed, short, durable, evidence, logic):
        assert marker in record["provenance"]
        assert record["layer_contract_protected"] is True
    assert recalled["results"][0]["vine_id"] == logic["vine_id"]
    assert marker in recalled["results"][0]["provenance"]
    assert context["logic_roots"][0]["vine_id"] == logic["vine_id"]
    assert {item["vine_id"] for item in context["evidence"]} == {
        durable["vine_id"],
        evidence["vine_id"],
    }
    assert inventory["inventory_only"] is True
    assert inventory["semantic_retrieval_performed"] is False
    assert inventory["lifecycle_mutated"] is False
    assert {item["vine_id"] for item in inventory["results"]} == {
        durable["vine_id"],
        logic["vine_id"],
    }
    assert doctor["memory_layers"]["all_records_shielded"] is True
    assert doctor["memory_layers"]["counts"] == {
        "live": 1,
        "short_term": 1,
        "long_term": 1,
        "contextual_logic": 1,
    }


def test_every_full_host_shares_one_serialized_memory_authority(
    tmp_path: Path,
) -> None:
    profile = "shared-host-conformance"

    def factory() -> AgentMemory:
        return AgentMemory(
            tmp_path,
            profile=profile,
            scope="local-user",
            profile_lock_timeout_seconds=5.0,
        )

    servers = {
        host: McpServer(memory_factory=factory, caller=host) for host in FULL_TOOL_HOSTS
    }

    def write(index_and_host: tuple[int, str]) -> dict[str, Any]:
        index, host = index_and_host
        marker = f"shared authority marker {index} {host}"
        return _tool_call(
            servers[host],
            100 + index,
            "echo_veil_remember",
            {
                "topic": marker,
                "payload": f"{marker} passed its caller-bound write.",
                "provenance": ["receipt:shared-authority-gate"],
            },
        )

    with ThreadPoolExecutor(max_workers=4) as pool:
        writes = list(pool.map(write, enumerate(FULL_TOOL_HOSTS)))

    assert len(writes) == len(FULL_TOOL_HOSTS)
    for host, record in zip(FULL_TOOL_HOSTS, writes):
        assert record["memory_layer"] == "short_term"
        assert record["layer_contract_protected"] is True
        assert record["provenance"] == [
            f"caller:{host}",
            "receipt:shared-authority-gate",
        ]

    for index, host in enumerate(FULL_TOOL_HOSTS):
        next_index = (index + 1) % len(FULL_TOOL_HOSTS)
        next_host = FULL_TOOL_HOSTS[next_index]
        marker = f"shared authority marker {next_index} {next_host}"
        recalled = _tool_call(
            servers[host],
            200 + index,
            "echo_veil_recall",
            {"query": marker, "top_k": 2},
        )
        assert recalled["results"][0]["topic"] == marker
        assert f"caller:{next_host}" in recalled["results"][0]["provenance"]

    doctor = _tool_call(
        servers[FULL_TOOL_HOSTS[0]],
        300,
        "echo_veil_doctor",
        {},
    )
    assert doctor["active_count"] == len(FULL_TOOL_HOSTS)
    assert doctor["memory_layers"]["counts"] == {
        "live": 0,
        "short_term": len(FULL_TOOL_HOSTS),
        "long_term": 0,
        "contextual_logic": 0,
    }
    assert doctor["memory_layers"]["all_records_shielded"] is True
    assert doctor["writer_serialization"] == "profile-sqlite-lease"
    assert doctor["shared_profile_safe"] is True


def test_adapter_artifacts_have_no_developer_paths_or_personal_identity() -> None:
    files: list[Path] = [
        ROOT / ".agents/plugins/marketplace.json",
        ROOT / ".claude-plugin/marketplace.json",
        ROOT / ".codex-plugin/plugin.json",
        ROOT / ".mcp.json",
        ROOT / "hooks/hooks.json",
    ]
    for root in (ROOT / "integrations", ROOT / "skills"):
        for directory, child_directories, filenames in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            child_directories[:] = sorted(
                name for name in child_directories if name != "node_modules"
            )
            current = Path(directory)
            files.extend(
                current / name
                for name in sorted(filenames)
                if (current / name).suffix
                in {".js", ".json", ".md", ".sh", ".ts", ".yaml", ".yml"}
            )
    for path in files:
        text = path.read_text(encoding="utf-8", errors="strict")
        assert "/Users/" not in text, path
        assert "scottwhitlock" not in text.casefold(), path
        assert "shell: true" not in text, path
