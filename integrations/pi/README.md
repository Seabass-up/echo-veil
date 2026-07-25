# Echo Veil for Pi

This native Pi extension registers `echo_veil_remember`,
`echo_veil_refresh_live`, `echo_veil_promote`, `echo_veil_recall`,
`echo_veil_context`, `echo_veil_list`, `echo_veil_forget`, and
`echo_veil_doctor` without adding a shell-enabled tool. It sends bounded JSON
to `echo-veil-agent` over stdin and defaults to the shared
`echo-universal-qwen3-v1` profile with scope `local-user`. This shared default
is only for harnesses acting for that same local user and authorization domain;
configure a distinct profile for another trust boundary. Each RPC process
releases the profile before returning, so Pi does not retain a writer lease
between calls.
The package also declares `skills/echo-veil-memory/SKILL.md`, so Pi discovers
the same fail-closed preflight, minimal-recall, Contextual Logic, and
layer-discipline ritual used by Codex, Claude Code, and Hermes.

The extension enforces that ritual in Pi's runtime:

- the first protected turn in each session validates doctor readiness;
- every accepted non-empty idle input performs a two-slot, non-inferential
  recall before model execution;
- causal and decision questions add a depth-two, eight-record Contextual Logic
  trace;
- skill or template expansion that changes the prompt triggers a second recall
  against the expanded intent;
- at most 16,000 characters of authenticated results are injected as explicitly
  untrusted JSON, with ambiguity, conflict, layer, confidence, and provenance
  preserved; and
- a failed or missing preflight blocks the input or aborts the agent run before
  a provider request. Pi tools remain blocked outside an authorized turn and
  no host-memory fallback is consulted.

Mid-run steering and queued follow-up inputs are rejected because Pi can add
them to an existing agent loop without a fresh `before_agent_start` boundary.
Retry that input after the current run settles so it receives its own protected
preflight.

From an Echo Veil checkout:

```bash
npm --prefix integrations/pi ci --ignore-scripts
npm --prefix integrations/pi audit --audit-level=high
npm --prefix integrations/pi run check
npm --prefix integrations/pi test
pi install ./integrations/pi
```

The linked checkout is detected automatically. For a standalone package,
install the `echo-veil-agent` command or set `ECHO_VEIL_AGENT_COMMAND` to its
executable path. `/echo-veil-doctor` validates the local shield without a model
call. `/echo-veil-preflight <intent>` exercises protected recall and Contextual
Logic without a model call. Neither diagnostic authorizes the next turn.

Remember and forget remain explicit user-authorized actions. The preflight
does not create memories or copy prompts into Echo Veil; it submits the bounded
intent for local retrieval and injects only the minimal validated result into
that model turn.
Remember creates Live, Short-Term, or typed Contextual Logic records;
Long-Term requires explicit promotion. The complete semantic contract is
record-bound ciphertext under the same scoped profile shield as payloads and
vectors.
Write compact seed crystals instead of transcript dumps. Transcript-shaped
payloads are accepted only as bounded Live state. Use
`echo_veil_refresh_live` to renew unchanged state or create a protected
superseding Live version when the content changes.
Recall preserves both leading candidates when `ranking_ambiguous=true` and
every returned possible-conflict group member when
`competing_memory_detected=true`; it never invents a conflict resolution.
Responses marked `degraded=true` are conservative lexical availability hints,
not semantic or authoritative recall.
Recall can restrict results to named semantic layers without changing scores.
Context tracing preserves root confidence gates and follows only bounded,
authenticated outgoing links; linked evidence is not an independent query
match and the tool does not synthesize an answer.
`echo_veil_list` is bounded administrative inventory, not semantic recall. It
does not reinforce or decay records and must not be injected wholesale into
model context.
The child receives only runtime essentials and the explicit local-adapter
environment allowlist; unrelated API keys and production Echo Veil crypto
secrets are not inherited. Child stderr is drained but never exposed to the
agent, and timeout/abort handling escalates from termination to forced exit.
The child also binds `caller:pi` into protected write provenance. That
transport marker does not count as durable Long-Term or Contextual Logic
evidence by itself.
