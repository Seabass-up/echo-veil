# Echo Veil for Grok Build

This plugin is the first-class Grok connector. It installs the shared
`echo-veil-memory` skill, a stdio MCP server bound to `caller:grok-build`,
and hooks that use the installed `echo-veil-preflight-hook` entry point with
the shared `echo-universal-qwen3-v1` profile.

Grok is not a singular fail-closed host. `UserPromptSubmit` is non-blocking,
and hook failures fail open. The prompt hook emits best-effort context or a
warning, but consumption of that output by Grok has not been qualified. Use the
Echo MCP tools and skill for protected recall in the current session.

The `PreToolUse` guard returns Grok's native top-level
`{"decision":"deny","reason":"..."}` response for `spawn_subagent` / `Task`,
including malformed requests. Grok's documented decision contract does not
provide a qualified path for delivering rewritten input to the child. These
guarded spawns are therefore denied even when parent-side recall would succeed;
the guard does not open memory or call an embedding provider first. Hook crashes,
timeouts, missing binaries, and disabled plugins still follow Grok's fail-open
behavior, so this guard is not a universal host isolation claim. Wiki pages,
source files, and other host evidence remain valid when Echo has no answer.

```bash
# From this repository
grok plugin validate ./integrations/grok
grok plugin marketplace add .
grok plugin install echo-veil --trust
```

For a standalone folder install:

```bash
grok plugin install /absolute/path/to/echo-veil/integrations/grok --trust
```

Install the matching `echo-veil-agent` and `echo-veil-preflight-hook`
distribution first. Plugin loading is useful without those binaries only as a
skill; hooks and MCP fail closed or fail open according to the host rules
above.

A standalone MCP add, without hooks, is:

```bash
# Configure the same env as integrations/grok/.mcp.json
echo-veil-agent --profile echo-universal-qwen3-v1 --scope local-user \
  --caller grok-build mcp
```

The bundled transport adds `caller:grok-build` to protected write provenance.
That marker identifies the invoking harness and is not sufficient evidence for
Long-Term promotion or Contextual Logic by itself.

Ordinary recall is lifecycle-neutral. Decay is not a side effect of asking a
question.

The shield applies only to records routed through Echo tools. Grok transcripts,
skills, settings, source files, and any separate native memory remain outside
it.
