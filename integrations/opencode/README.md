# OpenCode integration

This bundle combines the canonical nine-tool Echo Veil MCP adapter, the
`echo-veil-memory` skill, and a local OpenCode plugin that enforces protected
recall before provider execution.

Copy `opencode.json` into the applicable OpenCode configuration and copy the
contents of `.opencode` to either the project `.opencode` directory or the
global `~/.config/opencode` directory. OpenCode automatically loads JavaScript
plugins from its `plugins` directory. Install the matching Echo Veil Python
distribution so `echo-veil-agent` is available, and install
`qwen3-embedding:latest` in loopback-only Ollama.

The plugin:

- runs the canonical semantic doctor plus two-slot, non-inferential recall at
  `chat.message`;
- injects only bounded, escaped, provenance-bearing memory evidence;
- requires a matching preflight again at `chat.params`, immediately before the
  provider request is assembled;
- preflights and rewrites supported `Task` prompts before subagent creation;
- disables automatic post-compaction continuation because that synthetic turn
  has no fresh user intent to bind; and
- emits one generic error and stops when Echo, Qwen3, profile integrity, or the
  plugin contract is unavailable.

The child process receives an explicit environment allowlist and fixed
executable, profile, scope, caller, model, and dimension values. The plugin
never invokes a shell and never exposes child stderr.

Validate the repository adapter:

```bash
npm --prefix integrations/opencode run check
npm --prefix integrations/opencode test
opencode mcp list
```

For an installed fail-closed smoke, set
`ECHO_VEIL_FORCE_PREFLIGHT_FAILURE=1` for one isolated `opencode run`. The turn
must fail before any assistant token event. The variable is a deny-only
qualification control: it never reaches the child and cannot redirect
execution.

To isolate the child boundary without failing the root, set
`ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE=1` for one normal, non-`--pure`
`opencode run` that instructs the model to use `Task`. The root preflight and
provider request must succeed, the `tool.execute.before` hook must return the
generic failure, and no child model may start. This variable is deny-only and
must be unset after the smoke.

This proves the normal OpenCode plugin pipeline for the tested host version. It
does not cover `--pure`, which intentionally disables external plugins, future
host versions with changed hook ordering, or any out-of-band provider path
that bypasses `chat.message` and `chat.params`. Re-run the healthy and outage
smokes after every OpenCode upgrade.
