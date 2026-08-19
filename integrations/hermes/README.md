# Echo Veil for Hermes Agent

Hermes 0.18.2 exposes a `pre_llm_call` observer hook and an
`llm_execution` middleware boundary. The bundled `echo-veil-shield` plugin
pairs them:

1. the hook runs the canonical doctor-backed Echo preflight and returns a
   bounded, ephemeral protected-context block;
2. the middleware admits a provider call only when the exact
   session/task/turn tuple has that successful preflight attestation and its
   random per-turn nonce survives inside the complete protected-context
   envelope of a provider-visible user message; and
3. a missing, malformed, timed-out, oversized, or semantically unavailable
   preflight returns a zero-usage blocked response without calling the provider.

The plugin invokes a fixed `echo-veil-agent` command with `shell=False`, a
bounded request/response, a timeout, a child-environment allowlist, profile
`echo-universal-qwen3-v1`, scope `local-user`, caller `hermes`, and
`qwen3-embedding:latest` at 1,024 dimensions. Protected hook context is capped
below Hermes's default spill threshold so it stays ephemeral rather than being
written to a spill file.

The execution check deliberately ignores tool schemas, tool outputs, system
messages, and request metadata. Large tool-driven turns therefore cannot
exhaust validation by expanding unrelated request fields, and a copied nonce
outside user-message text cannot satisfy the gate. Validation remains bounded
and fail-closed. Denials log only stable reason codes and a normalized API mode;
they do not log prompts, protected context, nonces, identifiers, backend error
details, or request payloads.

Hermes may expand a slash-invoked skill into a current user message larger
than Echo Veil's 20,000-character semantic-query limit. For preflight only,
the plugin deterministically retains both ends of that current prompt with an
explicit middle-omission marker. The provider-facing user message is not
truncated, and it must still contain the complete protected-context envelope
before the provider is admitted.

Install the Python command first. Then place the plugin at
`~/.hermes/plugins/echo-veil-shield/`, enable `echo-veil-shield` under
`plugins.enabled` in `~/.hermes/config.yaml`, and merge
`integrations/hermes/config.yaml`. For singular mutable-memory mode, also set
both `memory.memory_enabled` and `memory.user_profile_enabled` to `false`.

```bash
hermes plugins list
hermes mcp test echo-veil
```

Run the repository plugin tests and an installed healthy/outage smoke before
relying on the boundary. The outage control
`ECHO_VEIL_FORCE_HERMES_PREFLIGHT_FAILURE=1` is deny-only: it is not forwarded
to the child process and cannot select a different executable or provider.

For a host-startup boundary that does not depend on Hermes treating general
plugins as required, use the shield-owned headless command:

```bash
printf '%s' 'Recall the smallest relevant project context.' |
  echo-veil-shielded-run hermes \
    --model qwen3.6:35b-mlx \
    --cwd /absolute/path/to/project
```

This path completes semantic preflight before Hermes starts, copies only the
digest-bound `echo-veil-shield` plugin into a temporary owner-only
`HERMES_HOME`, writes a fixed configuration with both native memory writers
disabled, and binds the turn to a random launch nonce. The plugin registers the
dedicated `hermes echo-veil-run` subcommand last, after its pre-LLM hook and
provider middleware. If plugin import or any required registration fails, that
subcommand does not exist and the model path is unreachable. The command uses
one fixed loopback Ollama provider, exposes only the Echo MCP toolset, and
deletes Hermes session/config state after the turn. It does not borrow the
operator's ambient Hermes configuration, memories, skills, sessions, or
plugins.

Hermes general plugins are opt-in and a plugin import/registration failure does
not abort host startup. The model-execution gate is therefore hard only while
the installed plugin is visibly loaded in ordinary plugin mode. Hermes does not
currently expose a required-plugin startup policy, so operators must verify
plugin status after updates and must not use a mode that suppresses plugins.
The shield-owned `echo-veil-run` path avoids that startup ambiguity but is
intentionally a local, Echo-tools-only, one-turn boundary rather than a claim
over every Hermes mode. Static skills, transcripts, project files, and session
history remain outside Echo Veil's cryptographic shield and are not a second
mutable memory authority.
