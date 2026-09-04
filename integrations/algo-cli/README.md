# Echo Veil for Algo CLI

Algo CLI uses Echo Veil through its in-process Python bridge rather than
starting a second MCP server. In required-protection mode, Echo Veil is the only
mutable memory authority: ordinary memory writes go to protected Short-Term
records, protected recall is assembled into prompt context, and the legacy
RAM/file catalog is neither loaded nor searched as a fallback.

Algo also injects Echo's four-layer operating ritual into ordinary chat and
every Agent Block system prompt. Each substantive turn performs doctor-backed
protected recall before model execution, admitting at most three ranked
records into the model prompt. A strictly closed-form response still performs
the doctor-backed shield preflight but omits semantic payloads and tool schemas
that cannot affect its answer. The prompt requires Contextual Logic for causal
or decision questions, preserves ambiguity and competing records, limits
writes to compact seed crystals, and never treats degraded recall as semantic
or authoritative. If required context cannot be built, Algo stops before the
first model call and does not expose the underlying backend error.

The bridge defaults to:

- profile `echo-universal-qwen3-v1`;
- authorization scope `local-user`;
- `qwen3-embedding:latest` with 1,024-dimensional output; and
- a bounded 16,384-token CPU embedding runtime released after each operation,
  preventing the protected recall model from evicting or throttling a large
  local agent model in GPU residency; and
- `caller:algo-cli` transport attribution plus `algo-cli:<source>` evidence.

The canonical profile is shared only with harnesses acting for the same local
user and authorization domain. Algo opens and closes its adapter per memory
operation; it does not retain a process-lifetime writer lease. A concurrent
Codex, Claude Code, OpenClaw, or other bundled adapter therefore waits on the
same bounded Echo lease and cannot persist a stale Live L1 snapshot.
The CPU placement, bounded context, and immediate release change resource
residency only: the semantic doctor and recall still finish before model
execution, and an unavailable embedder still fails closed or enters Echo's
explicit keyed read-only mode.

Do not silently repoint a non-empty existing profile. Inspect its readiness and
embedding identity first, then use `scripts/migrate_agent_profile.py` to
rehydrate one compatible source into the fresh canonical target without a
plaintext export. The source remains intact for rollback. A target must be
empty, and multiple non-empty sources must never be silently merged. An empty
older Algo profile may be retired from configuration only after its zero
payload count is recorded.

Algo's legacy `memory.json` is not part of the shield. Review it with the
bounded, payload-silent dry run before deciding whether any record belongs in
Echo:

```bash
uv run --locked python scripts/migrate_host_memory.py \
  --source ~/.algo_cli/memory.json \
  --profile echo-universal-qwen3-v1 --scope local-user --caller algo-cli
```

The source must be an owner-only JSON list of at most 200 strings. The dry run
reports only counts, record indices, risk categories, and hashes; it performs
no protected write. Review every flagged index in a local trusted editor.
Import the reviewed, eligible seed crystals only by repeating the command with
the exact `--confirm IMPORT_REVIEWED_HOST_MEMORY` phrase. Add
`--allow-review-required` only after manually approving every flagged record.

The import writes protected Short-Term records, deduplicates exact retries,
reopens the profile, and launches a separate read-only verifier process before
writing an owner-only hash receipt. It retains the plaintext source by default.
Retirement additionally requires `--retire-source` and the exact
`--retire-confirm RETIRE_VERIFIED_PLAINTEXT_SOURCE` phrase. Retirement is a
logical unlink after verification, not a guarantee of physical secure erase.
Never automate the review override or retirement confirmations.

Algo's current source accepts `>=0.6.0,<0.9.0` only in optional mode. Required
mode additionally binds Echo 0.8.0 to the exact VCS identity
`271ebaa959aabd7a83cf338d30cd0fa1c7338488` and an Algo-owned source digest.
A newer same-version wheel does not satisfy that existing identity gate.
Requalify and release the Algo consumer against the new Echo identity before
changing its installation; do not merely loosen the version range or refresh
the digest. Editable and source-only imports remain disallowed.

Algo CLI must preserve the complete four-layer contract:

- Live refresh creates a protected superseding version when content changes.
- Long-Term is reachable only by an explicit Short-Term promotion with a reason
  and non-caller evidence.
- Contextual Logic keeps its authenticated outgoing evidence trace and never
  synthesizes a conflict resolution.
- Ambiguous and possible-conflict candidates remain together.
- An Ollama outage allows only explicitly degraded keyed read-only recall;
  writes, promotion, refresh, reindexing, and lifecycle mutation stay blocked.

The Algo model-facing registry uses the same nine operation names as the
bundled MCP hosts:

- `echo_veil_remember`, `echo_veil_refresh_live`, and `echo_veil_promote`;
- `echo_veil_recall`, `echo_veil_context`, and `echo_veil_list`;
- `echo_veil_forget`, `echo_veil_doctor`, and `echo_veil_reindex`.

Those names are protection-required operations and never fall back to Algo's
legacy memory. Inventory and doctor are lifecycle-neutral observations. Recall
and context preserve Echo's explicit lifecycle-mutation metadata and require a
session preapproval. Remember, refresh, promote, forget, and reindex are
governed local mutations that require the Algo runtime's approval boundary.
Direct Long-Term creation remains prohibited; it requires an ordered,
reason-bearing promotion.

Static harness records, source files, skills, configuration, and transcripts
remain outside Echo Veil's shield. They are source material, not a second
protected memory authority. Algo CLI must create a bounded seed crystal through
its Echo bridge before describing continuity as protected.

Before enabling required mode, run Algo CLI's Echo readiness and regression
gates against the installed distribution. Availability or import alone is not
proof that protected write, retrieval, persistence, restart restoration,
four-layer metadata, context tracing, conflict preservation, and content policy
are all wired.

The 2026-07-25 installed-runtime QoS qualification used Algo's configured
default working directory. A cold closed-form Qwen3.6 35B turn completed in
15.95 seconds with a 2,745-token prompt and no tools; a substantive
memory-dependent turn completed in 22.82 seconds with three protected
candidates, a 4,776-token prompt, and no tool calls. The normal ChatGPT/Codex
route completed that memory-dependent turn in 10.26 seconds. These results
replace the earlier 220.5-second stalled run, but remain measurements from one
48 GB Apple-silicon host rather than universal latency guarantees.
