# Echo Veil for Claude Code

This plugin invokes the installed `echo-veil-agent` and
`echo-veil-preflight-hook` entry points and uses the shared
`echo-universal-qwen3-v1` profile with an explicit `local-user` authorization
scope. Install the matching Echo Veil distribution before enabling the plugin;
plugin loading fails closed when either executable is absent. The MCP transport
releases its startup probe and opens one bounded profile lease per tool call, so
other same-user harnesses can serialize on the profile without a lifetime
writer lease. Use a distinct profile for a different user or trust boundary.

```bash
claude plugin validate ./integrations/claude-code
```

For a local all-in-one installation from this repository:

```bash
claude plugin marketplace add .
claude plugin install echo-veil@echo-veil-local --scope user
```

Claude Code auto-memory is enabled by default and is not protected by Echo.
For singular authority, keep plugin hooks enabled and add both controls to the
user settings at `~/.claude/settings.json`:

```json
{
  "autoMemoryEnabled": false,
  "env": {
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"
  }
}
```

The environment control prevents Claude from creating or loading its native
auto-memory. The explicit setting makes that posture visible during review.
The Echo preflight also requires the environment control and blocks before
opening memory when it is missing.

The plugin also bundles the `echo-veil-memory` Agent Skill. Claude Code may
invoke it implicitly whenever prior work, decisions, preferences, open loops,
memory updates, contradictions, or decision rationale matter. The skill makes
Echo Veil the primary mutable memory store, requires doctor plus one
lifecycle-neutral recall at task start, uses Contextual Logic for “why,”
preserves ambiguity and competing records, and forbids a plaintext Echo
substitute. Wiki pages, source files, and curated documents remain valid
evidence when Echo has no answer.

The plugin's `UserPromptSubmit` and `PreToolUse(Agent)` hooks are its enforced
boundaries. The root hook runs before Claude processes the prompt. The Agent
hook runs before a supported subagent is created and rewrites only the complete
tool input's task field after task-specific recall succeeds. Both validate the
exact protected Qwen3 profile, recall two non-inferential candidates, add
bounded Contextual Logic for causal prompts, and inject only escaped,
size-bounded untrusted memory evidence. Any failure returns a generic
structured root stop or Agent-tool denial. An isolated Claude Code 2.1.207 root
outage qualification reported zero model turns, tokens, API duration, and cost.

Do not use `--safe-mode` or `--bare` for a singular-authority session: both
disable plugin hooks. A standalone `claude mcp add` installs tools but not this
pre-model gate. Supported subagents created through the `Agent` tool pass the
pre-execution gate. Claude Code's later `SubagentStart` event cannot block
creation, so Echo does not rely on it. Until the installed-host Agent-spawn
smoke passes, disable subagent use when the entire task requires fully qualified
singular-memory enforcement.

For a bounded child-only failure smoke, set
`ECHO_VEIL_FORCE_AGENT_PREFLIGHT_FAILURE=1` for one isolated normal plugin-mode
run that instructs Claude to use `Agent`. The root `UserPromptSubmit` preflight
must remain healthy, the `PreToolUse(Agent)` hook must return the generic denial,
and no child model may start. This deny-only control cannot authorize a turn,
change the profile, or redirect execution. Unset it after the smoke.

For a standalone installation, install `echo-veil-agent` and add it directly:

```bash
claude mcp add --transport stdio --scope user echo-veil -- \
  echo-veil-agent --profile echo-universal-qwen3-v1 --scope local-user \
    --caller claude-code mcp
```

Claude Code asks before trusting project MCP configuration. Review this plugin
and keep remember/refresh/promote/forget under user approval. Long-Term records must be
promoted from Short-Term with an explicit reason; the server returns the
shielded layer, provenance, and recommendations with recall results. Use
`echo_veil_refresh_live` only for bounded active state: unchanged content
renews its protected contract, while changed content creates a separately
protected superseding version. Write compact seed crystals rather than
transcript dumps; transcript-shaped content is accepted only in Live. Use
`echo_veil_context` for a bounded trace from confidence-checked Contextual Logic
roots to authenticated outgoing evidence links; those links are not independent
query matches and the tool does not synthesize an answer. Preserve every member
when recall reports `competing_memory_detected=true`; review the evidence rather
than inventing a resolution.

The shield applies only to records routed through these Echo tools. Claude Code
transcripts, skills, settings, source files, and any separate native memory
remain outside it; do not describe those host assets as encrypted by Echo or use
them as a silent fallback for protected memory.
Memory selected for a model turn is necessarily copied into authorized model
context and may be retained in the Claude Code transcript. The hook minimizes
and bounds that evidence, but it does not claim to encrypt Claude's transcript.

The bundled transport adds `caller:claude-code` to protected write provenance.
That marker identifies the invoking harness but is not sufficient evidence for
Long-Term promotion or Contextual Logic by itself.
