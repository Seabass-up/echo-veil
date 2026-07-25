# Echo Veil for OpenClaw

This exclusive memory plugin exposes `echo_veil_remember`, `echo_veil_refresh_live`,
`echo_veil_promote`, `echo_veil_recall`, `echo_veil_context`,
`echo_veil_list`, `echo_veil_forget`, `echo_veil_doctor`, and
`echo_veil_reindex`. It delegates to
the repository's Python adapter so OpenClaw and Codex use the same storage,
encryption, decay, and confidence policy.

For local development, link this directory so the plugin can auto-detect the
repository three levels above it:

```bash
openclaw plugins install -l ./integrations/openclaw
openclaw plugins inspect echo-veil --runtime --json
openclaw plugins doctor
```

Do not use that linked-checkout path for a singular-memory deployment. Build the
Python wheel and OpenClaw package twice, compare their hashes, install the
reviewed plugin archive with `openclaw plugins install`, and install the exact
wheel by a `file:` URL carrying its `#sha256=` fragment. Configure
`plugins.entries.echo-veil.config.executable` to that wheel's console script,
leave `plugins.load.paths` empty, and do not configure `projectPath`. The
current reviewed artifact identities and profile contract are recorded in
`deployment-lock.json`.

The main agent's `tools.alsoAllow` must include all nine tool IDs named above;
plugin registration alone does not make them available to that agent. Keep an
explicit `plugins.allow` inventory, disable `session-memory`, and run:

```bash
python scripts/verify_openclaw_deployment.py --text
```

The verifier is payload-silent. It checks the active gateway, exclusive memory
slot, agent/model policy, all nine tools, all three hooks, the managed archive,
the PEP 610 wheel receipt and installed Python bytes, owner-only profile
directories, the OpenClaw security audit, and Echo doctor health. Add
`--require-production-ready` only after the external enclave and cryptographic
review are actually complete; local AES-GCM staging is expected to fail that
stronger gate.

Installation selects `echo-veil` for OpenClaw's exclusive `plugins.slots.memory`
slot. It disables the prior provider as an active authority without deleting
that provider's files, so rollback and reviewed rehydration remain possible.
Runtime inspection must report `kind=memory`, `memorySlotSelected=true`, status
`loaded`, the exact nine tools, and no diagnostics.

Singular-authority mode also requires the hard turn gate. Enable the two
permissions Echo needs to read the current prompt and inject the protected
context:

```bash
openclaw config set plugins.entries.echo-veil.hooks.allowConversationAccess true --strict-json
openclaw config set plugins.entries.echo-veil.hooks.allowPromptInjection true --strict-json
```

For every model that may serve a protected session, set its model-scoped
`agentRuntime.id` to `openclaw`. For example:

```bash
openclaw config set \
  'agents.defaults.models["openai/your-model"].agentRuntime.id' \
  '"openclaw"' --strict-json
```

Echo's `before_agent_reply` hook claims the request early,
`before_prompt_build` injects bounded semantic context plus a random
short-lived attestation, and `before_agent_run` consumes that attestation once
before model execution. OpenClaw's native Codex app-server fast path does not
currently invoke the early-reply and pre-model hook pair. It is therefore not a
qualified singular-authority route even though the prompt-build hook runs.
Provider authentication can still use the supported ChatGPT/Codex OAuth route
while the agent runtime remains `openclaw`.

The package keeps OpenClaw as a peer rather than vendoring the host runtime or
its dependency tree. Run `npm run plugin:validate` with the supported OpenClaw
CLI installed before a release. That command builds the distribution, links it
into a disposable isolated OpenClaw state directory, selects its memory slot,
loads the real runtime, verifies all nine tools, runs plugin doctor, and removes
the temporary state.

For a copied or packaged install, install the artifact-bound
`echo-veil-agent` console script. `projectPath` is development-only and is
rejected by the deployment verifier. `stateDir` and `profile` select the encrypted local profile. Codex and
OpenClaw share memories only when both are configured with the same values.
The default is `echo-universal-qwen3-v1` with scope `local-user`, for harnesses
acting in that same local authorization domain. Each native tool invocation
uses a bounded fresh-process RPC and releases the profile before returning, so
OpenClaw does not retain a writer lease between calls. Configure a separate
profile for a different user or trust boundary.

When selected, Echo Veil is OpenClaw's only mutable agent-memory authority.
Its memory capability adds a mandatory prompt ritual: doctor-backed startup,
minimal recall for substantive work, Contextual Logic tracing for “why,”
ambiguity and conflict preservation, disciplined four-layer writes, and no
plaintext host-memory fallback. It does not capture every message. Useful
outcomes are stored only through an explicit Echo tool operation, and legacy
memory files remain read-only source evidence until a reviewed migration.

Remember creates only Live, Short-Term, or typed Contextual Logic records.
Long-Term requires the promotion tool and an explicit reason. Layer,
provenance, retention state, ordered promotion evidence, and Contextual Logic
links are authenticated ciphertext under the same scoped profile shield as the
payload and retrieval vectors.
Write compact seed crystals instead of transcript dumps. Transcript-shaped
payloads are accepted only as bounded Live state. Use
`echo_veil_refresh_live` to renew unchanged state or create a protected
superseding Live version when the content changes.

Recall preserves both leading candidates when `ranking_ambiguous=true` and
every returned possible-conflict group member when
`competing_memory_detected=true`. Possible conflicts share an authenticated
protected topic; Echo Veil does not infer incompatibility or a resolution.
Results labelled `degraded=true` remain non-semantic, non-authoritative
availability hints. Recall supports an optional layer scope without score rewriting.
Context tracing preserves root gates and follows only bounded authenticated
outgoing links; its evidence is not independently query-scored and it does not
synthesize an answer. Each response includes `host_transport.elapsed_ms` so fresh-process RPC
overhead can be tracked separately from Echo Veil's in-process recall time.
`echo_veil_list` is a bounded administrative inventory operation. It does not
perform semantic retrieval or lifecycle reinforcement and must not be used as
a bulk prompt-injection path.
The child receives only runtime essentials and the explicit local-adapter
environment allowlist; unrelated API keys and production Echo Veil crypto
secrets are not inherited. Child stderr is drained but never returned to the
agent, and timeout/abort handling escalates from termination to forced exit.
The child also binds `caller:openclaw` into protected write provenance. That
transport marker does not count as durable Long-Term or Contextual Logic
evidence by itself.

Before enabling the gate for real work, simulate an Echo/Ollama outage and
confirm OpenClaw reports a hook block before model startup. Re-run that smoke
after any OpenClaw, plugin, model-route, or hook-permission change. A selected
memory slot, loaded tools, or prompt-only warning is not sufficient evidence of
a hard model gate.

OpenClaw's built-in `session-memory` hook writes recent transcript messages to
the workspace and would create a second mutable memory path. Disable it
explicitly:

```bash
openclaw config set hooks.internal.entries.session-memory.enabled false \
  --strict-json
```

The Echo plugin checks that setting together with the selected `memory` slot
and both required hook permissions. If any of them drift, the next protected
turn fails closed before model startup. Session transcripts and compaction
artifacts still remain host data outside Echo's shield; disabling
`session-memory` only removes the extra workspace-memory writer.
