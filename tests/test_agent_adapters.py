from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, cast


ROOT = Path(__file__).parents[1]
VERSION = "0.4.0"
HOSTS = (
    "openclaw",
    "hermes",
    "codex",
    "claude-code",
    "pi",
    "opencode",
    "droid",
    "goose",
    "mercury",
)


def _json(path: str) -> dict[str, object]:
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def _mapping(value: object) -> dict[str, Any]:
    return cast(dict[str, Any], value)


def test_plugin_versions_and_mcp_profiles_are_aligned() -> None:
    codex = _mapping(_mapping(_json(".mcp.json")["mcpServers"])["echo-veil"])
    claude = _mapping(
        _mapping(_json("integrations/claude-code/.mcp.json")["mcpServers"])["echo-veil"]
    )
    droid = _mapping(
        _mapping(_json("integrations/droid/.factory/mcp.json")["mcpServers"])[
            "echo-veil"
        ]
    )
    opencode = _mapping(
        _mapping(_json("integrations/opencode/opencode.json")["mcp"])["echo_veil"]
    )

    assert codex["env"]["ECHO_VEIL_PROFILE"] == "codex"
    assert claude["env"]["ECHO_VEIL_PROFILE"] == "claude-code"
    assert droid["args"] == ["--profile", "droid", "mcp"]
    assert opencode["command"] == [
        "echo-veil-agent",
        "--profile",
        "opencode",
        "mcp",
    ]

    for path in (
        ".codex-plugin/plugin.json",
        "integrations/claude-code/.claude-plugin/plugin.json",
        "integrations/openclaw/openclaw.plugin.json",
        "integrations/openclaw/package.json",
        "integrations/pi/package.json",
    ):
        assert _json(path)["version"] == VERSION


def test_text_configs_cover_every_host_and_preserve_security_boundary() -> None:
    integration_readme = (ROOT / "integrations/README.md").read_text(encoding="utf-8")
    for host in HOSTS:
        assert re.search(rf"\b{re.escape(host)}\b", integration_readme, re.IGNORECASE)

    hermes = (ROOT / "integrations/hermes/config.yaml").read_text(encoding="utf-8")
    goose = (ROOT / "integrations/goose/echo-veil.yaml").read_text(encoding="utf-8")
    mercury = (ROOT / "integrations/mercury/SKILL.md").read_text(encoding="utf-8")
    assert 'args: ["--profile", "hermes", "mcp"]' in hermes
    assert 'args: ["--profile", "goose", "mcp"]' in goose
    assert "allowed-tools:\n  - run_command" in mercury
    assert "must not send memory topics, payloads, queries" in mercury
    assert "full remember, recall, and forget operations are unavailable" in mercury


def test_adapter_artifacts_have_no_developer_paths_or_personal_identity() -> None:
    files = [
        path
        for path in (ROOT / "integrations").rglob("*")
        if path.is_file()
        and "node_modules" not in path.parts
        and "dist" not in path.parts
        and path.suffix in {".json", ".md", ".ts", ".yaml", ".yml"}
    ]
    for path in files:
        text = path.read_text(encoding="utf-8", errors="strict")
        assert "/Users/" not in text, path
        assert "scottwhitlock" not in text.casefold(), path
        assert "shell: true" not in text, path
