# Echo Veil for Droid

The Droid integration provides the nine-tool Echo Veil MCP surface, the
canonical memory skill, native lifecycle hooks, and a shield-owned headless
launcher.

- `UserPromptSubmit` retrieves and injects protected context before Droid
  processes a root prompt.
- `PreToolUse(Task)` retrieves task-specific context, preserves the complete
  Task input, and rewrites only its required `prompt` before a sub-droid starts.

Install the Echo Veil Python command and Qwen3 model first. A standard
`uv tool install` places the hook at
`$HOME/.local/bin/echo-veil-preflight-hook`, which the fixed wrapper uses
without a `PATH` lookup. If the tool is installed elsewhere, resolve the hook
entry point once and expose only its absolute executable path:

```bash
uv tool install --from /absolute/path/to/echo-veil echo-veil
ollama pull qwen3-embedding:latest
export ECHO_VEIL_PREFLIGHT_COMMAND="$(command -v echo-veil-preflight-hook)"
```

For project configuration, copy the committed `.factory` directory into the
target project. For a Droid marketplace package, use this directory as the
plugin root; it includes `.factory-plugin/plugin.json`, `hooks/`, `skills/`,
and `mcp.json`.

For a reviewed local checkout, register this repository as a local marketplace
and install the plugin at user scope for interactive Droid:

```bash
droid plugin marketplace add /absolute/path/to/echo-veil
droid plugin install echo-veil@echo-veil --scope user
droid plugin list --scope user
```

Choose either the marketplace plugin or manually copied user hooks. Loading
both runs the same preflight twice and can contend for the protected profile
lease.

The wrapper exits with Droid's blocking status `2` if the absolute command is
missing or fails. The hook commands intentionally omit a Droid timeout: a host
timeout is a non-blocking hook error, which is not an acceptable protected
memory boundary. The Python hook has its own bounded Ollama and profile-lock
timeouts and returns a structured stop on readiness, integrity, degradation,
or retrieval failure. These native hooks still require an installed interactive
runtime qualification.

## Headless `exec`

Droid 0.180.0 `exec` still bypasses both plugin and user `UserPromptSubmit` hooks. Do
not use bare `droid exec` for a protected-memory claim. Use the shield-owned
launcher instead:

```bash
printf '%s' 'Review the current task and report the next safe action.' |
  echo-veil-shielded-run droid \
    --model custom:qwen3.6:35b-mlx-0 \
    --cwd /absolute/path/to/project
```

The launcher reads the prompt from stdin, completes protected doctor and
semantic recall before starting Droid, and sends the bounded protected context
through child stdin. It disables Factory built-in skills and the `Task` tool
because `exec` cannot prove a task-specific child preflight. It does not expose
session-resume, fork, mission, or unsafe permission-bypass flags. On an Echo,
Qwen3, integrity, or recall failure, no Droid process starts.

Qualify the installed runtime before calling it singular authority:

1. Confirm `droid mcp list` shows Echo Veil and all nine tools.
2. Confirm a shielded headless prompt receives protected context.
3. Simulate an Ollama outage and confirm the shielded launcher starts no Droid
   process and returns no model usage.
4. Separately qualify interactive root and `Task` hooks after authenticating the
   interactive host.
5. Confirm an allowed interactive `Task` preserves `subagent_type`, `description`,
   `complexity`, background/resume fields, and attached image paths.

An organization setting with `allowManagedHooksOnly=true` can ignore local
plugin and project hooks. That installation is not qualified unless the Echo
Veil hooks are provisioned as managed hooks and the outage smoke still blocks.
