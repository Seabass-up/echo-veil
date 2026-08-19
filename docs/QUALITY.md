# Retrieval quality

Echo Veil's release gate measures retrieval behavior instead of treating an
installed embedding model as proof of quality.

## Current local result

On 2026-07-24, `qwen3-embedding:latest` at 1,024 dimensions passed the committed
neutral suite with:

- 42/42 correct top-1 results: 17 keyword, 19 paraphrase, 2 current-update,
  2 temporal, and 2 long-memory queries;
- 14/14 unrelated and same-subject/absent-fact queries rejected;
- 17/17 keyword records recovered and 14/14 distractors rejected through the
  read-only always-available layer with semantic embeddings unavailable;
- 1/1 protected Contextual Logic trace passed in semantic and read-only
  always-available modes, returning two authenticated evidence records with no
  query score or synthesized answer;
- 1/1 same-topic competing-memory probe preserved both authenticated current
  records from a `top_k=1` request in semantic and read-only always-available
  modes, without inferring compatibility or a resolution;
- 1/1 protected Live-refresh probe renewed unchanged state in place, created a
  shielded superseding version for changed content, survived restart and
  read-only reopen, and rejected a degraded write;
- 200.69 ms mean and 213.80 ms p95 recall;
- 1,979.00 ms for the cold first protected remember, including local model
  startup;
- 129.49 ms steady mean remember after that first operation;
- 208.45 ms for the semantic protected-context trace;
- 210.51 ms for the semantic competing-pair probe;
- 91.72 ms for a changed-content protected Live refresh; and
- 10.00 ms to reopen, authenticate the four-layer contracts, and restore the
  persisted profile.

The same committed corpus, queried through the installed OpenClaw memory-core
CLI, returned 32/42 correct top-1 results and rejected 9/14 distractors. Its
category result was 17/17 keyword, 10/19 paraphrase, 2/2 current-update, 1/2
temporal, and 2/2 long-memory. The CLI-level latency measurement includes host
process overhead and therefore is not used as a direct engine-latency claim.

This is a meaningful same-machine, same-corpus pilot result. It is not evidence
that Echo Veil is universally better than every memory product. The corpus is
small and synthetic, and the comparison covers retrieval rather than complete
capture, generation, cost, or multi-tenant operations.

## What the gate covers

The adapter combines:

- instruction-aware local Qwen3 query embeddings;
- a second predicate-focused answerability embedding that masks grammatical
  subjects and rejects subject-only matches at a separately calibrated `0.42`;
- AES-GCM-protected passage vectors and MaxSim for long memories;
- bounded candidate generation from live memory, persisted LSH, and lexical hits;
- keyed-hash lexical features, so searchable terms are not stored in plaintext;
- topic-aware maximal marginal relevance for result diversity;
- explicit `effective_at` and `supersedes` links for current and point-in-time
  truth;
- bounded authenticated same-topic pair preservation with a non-invented
  `possible_conflict` contract; and
- fail-closed embedding identity binding to model digest, dimension, and query
  instruction.

Broad retrieval and answerability queries are batched into one Ollama request.
The broad candidate threshold is `0.44`; candidates that pass it still must pass
the answerability gate. The committed hard negatives include unknown passport,
medication-allergy, shoe-size, and sports-team attributes for a person who does
have other stored records.

An additional 24-record host-profile pilot retained 8/8 keyword top-1 results,
improved exact-label paraphrase recall from 10/14 to 12/14, and improved
unrelated rejection from 6/10 to 10/10. The two remaining exact-label misses
returned relevant but broader or adjacent records at rank one, while both
intended records ranked second for 14/14 top-2 coverage. They remain visible as
ranking ambiguity rather than being hidden by corpus-specific rules.
Fresh-process RPC time averaged 335 ms with a 339 ms p95 on that run, down from
the pre-fix pilot's 1.89-second mean despite the added second-stage check.

The source payload, protected vectors, and keyed lexical index persist across a
restart. If Ollama or the configured model is unavailable, an existing profile
can provide explicitly degraded, read-only keyed recall without hashing or
lifecycle mutation. Model-identity changes, malformed responses, invalid keys,
and corrupt storage still fail closed.

The profile migration rehydrates content, the four-layer contract, and explicit
supersession history into new vine IDs without a plaintext export. It
intentionally does not copy lifecycle scores, reinforcement age, locks, or
archive position from the source profile.
The separate read-only migration verifier compares one-time in-process HMAC
tokens, effective times, remapped supersession edges, protected contracts, and
target index completeness. Tests cover scoped contract preservation, reviewed
target extras, legacy-to-Short-Term normalization, and content mismatch
rejection. It never emits payloads or stable per-record fingerprints.

The separate host-catalog migration gate covers a bounded JSON-list source. It
verifies payload-silent dry-run reporting, owner-only and no-symlink input
policy, transcript rejection, manual-review and exact-confirmation gates,
Unicode-safe retry deduplication, rollback before releasing the writer lease,
reopened-profile inventory, separate-process shield verification, owner-only
hash receipts, source retention on failure, and explicitly confirmed logical
retirement. This qualifies the workflow mechanics; it does not decide that a
host record is accurate, authorized, or worthy of promotion.

## Four-layer contract gate

The semantic-layer tests are separate from retrieval scoring. They exercise all
four roles through the real scoped-v2 adapter and verify:

- no layer, provenance, promotion reason, or Contextual Logic relationship is
  present in the stored contract envelope as plaintext;
- Long-Term cannot bypass Short-Term promotion and the complete ordered
  promotion history survives restart;
- expired Live records are erased without archival;
- unknown Contextual Logic links are rejected and source erasure removes
  transitive derived records;
- layer-scoped recall preserves the unfiltered score, and the Contextual Logic
  trace preserves ambiguous or gated roots while bounding outgoing traversal;
- current same-topic records remain paired in semantic and degraded recall,
  while superseded or point-in-time-invalid history does not create a false
  conflict group;
- a copied opaque topic token is rejected by the encrypted-record binding
  check before it can manufacture a conflict signal;
- linked context evidence authenticates independently, carries no fabricated
  query score, and is omitted after tampering or when invalid at `as_of`;
- missing or modified contracts fail closed; and
- the read-only availability path returns only records whose protected contract
  authenticates successfully.

These checks establish contract behavior and at-rest protection for the local
staging adapter. They do not establish enclave deployment, universal retrieval
quality, or physical erasure.

A parameterized contract-conformance gate runs the same write, Live refresh,
ordered promotion, layer-filtered recall, Contextual Logic trace, doctor, and
caller-provenance sequence through the real MCP dispatcher under the OpenClaw,
Hermes, Codex, Claude Code, Pi, OpenCode, Droid, and Goose identities. Native
OpenClaw and Pi packages retain their own transport tests. Algo CLI separately
runs the contract through its installed in-process bridge because it does not
spawn the MCP transport. Mercury remains a readiness-only skill until its host
exposes a safe structured-tool boundary and an all-native-memory-off or backend
replacement contract. Disabling Second Brain alone is not sufficient because
Mercury falls back to its basic Long-Term store while separate Short-Term and
Episodic stores remain constructed.

The adapter gate does not flatten host enforcement tiers. Algo CLI required
mode, OpenClaw models pinned to the OpenClaw runtime, Pi, and a loaded Hermes
shield plugin have
repository-owned pre-model stop boundaries, including tested outage paths.
OpenClaw's native Codex app-server path is excluded because it does not invoke
the early-reply and pre-model hook pair. Codex and Claude Code have hard root
hooks. Claude Code has a fail-closed `PreToolUse(Agent)` gate; Codex ships the
same bounded handler, but its installed collaboration router bypassed that
event and direct subagents are excluded. OpenCode now gates root turns through
`chat.message` plus a matching `chat.params` attestation and preflights
supported `Task` prompts before execution. Direct `SubagentStart` is not an
enforcement boundary in the current host APIs, and out-of-band spawn paths
remain unqualified. Hermes binds successful `pre_llm_call` context to the
exact session/task/turn plus a random request nonce and blocks provider
execution through `llm_execution` when either binding is absent. AIP enforces
a required Echo backend. Hermes ordinary plugin mode remains operationally
conditional because general plugins are opt-in and a registration failure does
not abort host startup. The shield-owned headless launcher preflights before
starting Codex, Droid, Goose, or Hermes. Its Codex path
ignores ambient user config, requires one Echo MCP server, and disables native
memory, Chronicle, goals, plugins, and parallel agents. Direct Codex
collaboration, bare Droid `exec`, interactive Droid, and normal Goose recipe
runs are outside that boundary.
Mercury remains readiness-only and blocked for singular authority.

The shared Python hook battery covers complete doctor validation, exact Qwen3
identity, two-slot non-inferential recall, causal Contextual Logic, hostile
memory escaping, omission rather than truncation of oversized payloads,
ambiguity and competing-pair preservation, bounded hook input, complete
Agent/Task argument preservation, task-field rewriting, fail-closed spawn
denial, generic payload-silent failures, and runtime semantic degradation after
a successful doctor. The battery also proves that Claude preflight stops before
opening Echo when the official native-auto-memory disable control is absent.
Claude Code 2.1.207 loaded the installed local-marketplace plugin with native
auto-memory disabled and, during a simulated Ollama outage, stopped in 105 ms
with zero model turns, input/output tokens, API duration, and cost. Codex
0.144.5 loaded the installed local-marketplace plugin after both exact hook
hashes were reviewed through `/hooks` and its native memory feature was
disabled; a fresh normal `codex exec` outage run then completed with zero input
and output tokens. The same run before trust review executed the model, which
is retained as evidence that installation alone is not a gate.
Repository tests and a separate live Qwen3 preflight cover the healthy shared
hook path. Installed-host Agent-spawn smokes remain separate release gates only
for host paths that actually expose a blockable event.

On 2026-07-25, bounded installed spawn attempts kept those gates open rather
than manufacturing a pass. Codex 0.144.5 completed a protected root turn and
reached its real collaboration router, but `codex exec` rejected one malformed
agent identifier and then failed a valid request with `no thread with id`.
Repeating the valid request with Echo's child-only deny control still reached
the collaboration router, proving that this Codex path did not invoke
`PreToolUse`; it is excluded rather than represented as a pending pass.
The shield-owned replacement then completed a real ephemeral, read-only Codex
turn with ambient user config ignored, strict config enabled, one required Echo
MCP server, and all current parallel-agent paths disabled. The first smoke
exposed an additional host leak: Codex still discovered the operator's global
skill and stale model cache, and a doctor-tool qualification consumed 87,027
input tokens. The launcher now gives Codex a temporary owner-only home
containing only its validated auth link. The final installed-wheel exact-marker
turn completed in 8.4 seconds with 18,636 input tokens and no ambient skill read
or model-cache warning. A one-doctor-call MCP proof completed in 11.7 seconds with
59,433 input tokens; the remaining cost includes Codex's base prompt and the
large structured doctor response, so normal launcher turns should not repeat
doctor after the launcher has already completed protected preflight. A
simulated semantic outage returned status 2 before Codex startup.
Claude Code 2.1.207 completed its protected root hook with full semantic
context, then reported that the host was not logged in before any model tokens
or Agent call. OpenCode 1.17.18 returned `401` on its authenticated provider;
its free-provider fallback produced no progress for two minutes and was
terminated. The child-only deny controls have repository coverage proving that
root preflight remains healthy while a delivered Agent/Task event stops before
opening Echo. A successful installed child plus an installed denied-child pair
is still required for Claude Code and OpenCode; direct Codex collaboration has
no qualified claim until the host exposes an enforceable boundary.

OpenClaw 2026.7.1-2 loaded the native plugin with all three hooks, selected Echo
as the exclusive memory slot, and passed a forced-outage turn through its
OpenClaw runtime: the early hook returned a synthetic block and the model did
not start. Its built-in `session-memory` writer is disabled. A hot-reload drift
test then re-enabled that writer; the first implementation exposed a cached
configuration bug and allowed a protected model turn. The guard now reads
OpenClaw's live runtime configuration at all three hook boundaries. Repeating
the drift test produced the generic block in 216 ms with no model usage. The
test also found that OpenClaw's native Codex app-server runtime skips the
early-reply and pre-model hooks. Protected OpenAI models were therefore pinned
to `agentRuntime.id="openclaw"`; future runtime changes require the outage
smoke again.

The final July 25 deployment recheck closed the later host-configuration drift
found by an independent review. The main agent now exposes all nine tools and
completed live `context` plus `list` calls. OpenClaw loads the plugin from the
reviewed archive rather than a linked checkout, and its explicit Python
executable is bound by PEP 610 to the reviewed wheel. The active extracted
entry point, archive, wheel, and installed Python package bytes all match the
public `deployment-lock.json`. A controlled live outage returned the generic
preflight-unavailable response with no provider name or token-usage record; the
restored runtime then completed a healthy protected turn. The stale
`memory-core` entry and mutable plugin load path are absent, the plugin
inventory is explicit, the two third-party npm specifications are exact, and
OpenClaw's security audit reports zero critical findings and zero warnings.
The Echo state parent, profile, and key directories are owner-only. A
disposable restored copy reopened all 59 shielded records with zero decrypt or
index failures. Time Machine reports the directory included, but its backup
destination was unavailable during this run, so an actual Time Machine restore
remains unproved. The deployment remains `local-staging` and
`production_ready=false`; none of this substitutes for the independent
cryptographic and enclave review.

Droid's root and Task wrapper has direct contract coverage for
absolute-executable validation, blocking status, complete Task-field
preservation, and no host-timeout bypass. Installed Droid 0.180.0 `exec`
nevertheless bypassed both plugin and user prompt hooks and completed a model
turn during a forced Echo outage. Bare `droid exec` is therefore unqualified.
The separate `echo-veil-shielded-run droid` boundary completed a healthy local
turn and returned on forced preflight failure before host creation. It disables
`Task`; interactive Droid remains separately unqualified.

Algo CLI's installed required-protection profile uses the current
hash-pinned 0.6.0 wheel and passed its readiness report plus focused
bridge/pipeline/harness suite. A healthy ordinary one-shot completed only after
the protected context build. A live disabled-Echo probe stopped before model
execution with zero rounds, zero generated tokens, and zero calls to the
counted `/api/chat` endpoint; only model-metadata endpoints were queried. An
Ollama-only outage is intentionally different: the encrypted keyed read-only
availability layer may support a clearly degraded model turn, while every
write and semantic claim remains blocked.

The 2026-07-25 recheck now passes 399 affected Algo source tests. Its normal
installed runtime reports an archive-pinned supported Echo distribution,
`all_records_shielded=true`, `local_protection_ready=true`, a per-operation
profile lease, and `production_ready=false`. The earlier 220.5-second local
large-model stall was traced to Echo's embedding runner sharing Ollama GPU
residency with the 35B agent model plus avoidable one-shot prompt material.
Algo now places the 16,384-token embedding runner on CPU, releases it
immediately after each protected operation, admits at most three protected
records, omits specialist Echo tools without explicit memory-operation intent,
and retains a doctor-only shield check for strictly closed-form responses.

Against the installed entry point and configured default working directory, a
cold closed-form Qwen3.6 35B probe completed in 15.95 seconds with zero tools
and a 2,745-token prompt. A substantive protected-memory query completed in
22.82 seconds with three bounded candidates, zero tool calls, and a 4,776-token
prompt. The normal ChatGPT/Codex route completed the same memory-dependent turn
in 10.26 seconds, including 7.66 seconds of local semantic context work. A
simulated Ollama outage still returned only degraded keyed read-only results,
reported semantic retrieval unavailable, left lifecycle state unchanged, and
blocked the write. These are single-machine qualification measurements, not a
universal latency guarantee.

The final Algo recheck installed the exact Echo wheel by its recorded archive
hash. An initial installer path that omitted the PEP 610 archive hash was
correctly rejected before any model round; the hash-bound installation then
completed a protected one-shot in 7.41 seconds. That run redacted its working
directory and emitted no numerical runtime warning or local source path.
Focused integration tests and the public-release privacy scan pass. Algo's full
suite reaches the coverage threshold but its release remains blocked by two
pre-existing governance checks: the dirty hardening change set is not fully
authorized in its ledger, and its recorded qualification source digest is
stale. Those repository-governance failures are not converted into an Echo
runtime pass.

The final 2026-07-25 artifact recheck upgraded only Echo Veil inside Algo's
isolated runtime to the twice-reproduced 0.6.0 wheel with SHA-256
`b66ce125ebf2ce066f6cbbb27077ba86780e217fd981a76d5f1515bc76a6766a`;
it did not rebuild or install Algo's dirty, frozen source tree. PEP 610 reports
that exact archive hash, and the installed Algo readiness boundary reports the
version supported, healthy, all records shielded, restart restoration and all
four lifecycle contracts wired, a per-operation shared-safe profile lease, and
`production_ready=false`. A path-silent closed-form turn then returned its
exact sentinel in one model round, zero tool calls, 3.97 seconds, valid NDJSON,
and no stderr. A required-mode disabled-Echo drill stopped with a sanitized
failure and zero provider calls. A simulated embedding outage remained
all-shielded, blocked writes and lifecycle mutation, and supplied the caller
both the degraded keyed-read-only and non-authoritative labels. The focused
Algo bridge, pipeline, and one-shot battery passes 150 tests. Its full suite
still has only the two governance failures above; the shield qualification
does not lift that release freeze.

AIP's separate source checkout now passes 273 repository tests plus its
dependency-light runner. A disposable live
profile then exercised its fresh-process RPC bridge through protected Live
write and changed-content refresh, ordered Short-Term and Long-Term promotion,
typed Contextual Logic over two evidence records, top-one layer-filtered
recall, authenticated two-record context, and fresh-store restart recall.
A simulated semantic outage returned `degraded=true`,
`semantic_available=false`, and `lifecycle_mutated=false`, and blocked a write.
AIP 0.1.1 now wraps every runtime provider before capability, workflow, Agent,
SDK, chat, streaming, or vision generation. A healthy installed-artifact probe
called the underlying provider once with exactly one protected context; a
simulated semantic outage called it zero times. Two independent builds produced
the same wheel and normalized sdist. The exact wheel SHA-256 is
`ffb845152beb7f110a4b3f0e5978497e0a7d5639a6a39576e6bb7d5fe7d5d005`;
the PEP 610 hash-fragment install returned `artifact_bound=true` and verified
every installed AIP Python source against its wheel `RECORD`. The Echo authority
verifier therefore reports the installed AIP boundary current. Manually
constructed raw providers outside AIP's runtime builder and production enclave
readiness remain outside this qualification.

Pi's native gate additionally tests full doctor validation, two-candidate
recall on every accepted turn, bounded Contextual Logic for causal prompts, hostile
memory-text escaping, ambiguity/conflict preservation, expanded-prompt
rechecks, rejection of mid-run follow-ups, tool denial outside an authorized
turn, and abort of an agent start that lacks protected preflight.

An isolated Pi 0.80.6 RPC qualification loaded the real extension once. A
fresh process completed protected Qwen3 recall plus Contextual Logic without a
model call through `/echo-veil-preflight`. With Echo unavailable, an ordinary
input was handled before `agent_start`. A separate extension-triggered turn
that bypassed Pi's input and `before_agent_start` hooks was stopped by the
agent-start guard with `stopReason=aborted`, zero model tokens, and no fallback.
This is evidence for that tested host version and boundary, not a compatibility
claim for future Pi releases.

OpenCode 1.17.18 loaded the installed global plugin and the current source-built
Echo entry point. A healthy run injected the protected marker and Echo
authority into the stored user message before completing. With the Echo command
blocked by the plugin's deny-only outage control, the same host returned only
an error event; its export contained zero assistant messages, tokens, and cost.
The repository plugin battery separately covers the `chat.params` backstop, generic
payload-silent failures, exact Task argument preservation, task-specific
preflight, and disabled automatic post-compaction continuation. `--pure`
deliberately disables external plugins and is outside this claim; installed
Task-spawn qualification remains a release gate.

Hermes Agent 0.18.2 loaded the installed `echo-veil-shield` plugin with one
`llm_execution` middleware, disabled both built-in mutable memory writers, and
connected all nine Echo tools. A healthy one-shot completed through the real
local provider after semantic preflight. The deny-only outage control returned
the generic blocked response with zero input, output, and total tokens; an
installed middleware probe counted zero calls to the provider terminal. Hermes
still reports one internal API attempt because the synthetic response travels
through its API loop. That counter is not a provider invocation. Plugin load
remains an operational gate because Hermes general-plugin registration failure
does not abort startup.

The shield-owned Hermes path removes that startup ambiguity for one bounded
headless mode. It validates the installed plugin against build-embedded
digests, copies only those bytes and a native-memory-off configuration into an
isolated temporary `HERMES_HOME`, binds the protected stdin prompt to a random
launch nonce, and requests the plugin-defined `echo-veil-run` command. That
command is registered last, after the required hook and `llm_execution`
middleware, and restricts Hermes one-shot execution to the Echo MCP toolset.
The source smoke completed the real local-provider marker
`ECHO_HERMES_SHIELDED_HEALTHY` in 23.26 seconds. The subsequent default-plugin
smoke installed the exact 0.6.0 wheel with SHA-256
`959becc9d9666d0c1069b68b5bca9970ea84fa0bf5c9b1908471826fcee496d2`
and completed the same marker through Hermes 0.18.2 in 79.27 seconds after a
cold local-model start. A forced outer semantic outage against that installed
wheel returned status 2 in 0.11 seconds before Hermes process creation. The
final repository gate passed 464 Python tests, Python lint/format/type checks,
all Rust checks, and the Worker, website, OpenClaw, and Pi tests. The qualified
claim is local, one-turn, and Echo-tools-only; ordinary plugin mode remains
conditional.

Isolated current-host smoke tests also connected Droid 0.180.0 to the Echo MCP
server. This proves tool availability, not hook execution. Goose 1.41.0
validated the recipe and invoked `echo_veil_doctor` through
the real recipe extension. The test also established that Goose's
`--no-profile` flag suppresses recipe-defined extensions, so the recipe and
documentation now stop and explain that boundary. After hardening, a second
isolated run invoked both doctor and two-slot, non-inferential recall through
the real extension and made no memory mutation. The normal recipe remains
policy-driven. The installed shield-owned headless launcher then passed a
healthy Ollama run both with Echo alone and with the reviewed `developer`
builtin. A forced semantic-preflight outage returned status 2 before Goose
startup.

A separate shared-authority gate starts all eight full tool-host callers
against one scoped profile, performs their writes concurrently through the
profile lease, and requires each host to recall the next host's record with the
originating caller provenance intact. The final doctor report must show a
complete shielded index and
`writer_serialization=profile-sqlite-lease`.

The live gate also creates one shielded Contextual Logic record over two
benchmark memories and two same-topic current records for the competing-memory
probe. It creates and renews one Live record, then creates a shielded superseding
Live version when that content changes. It exercises protected context,
competing-pair preservation, and Live version persistence through both Qwen3
and the simulated-outage reader. Those probes are reported separately from the
42 retrieval queries so linked, paired, or lifecycle evidence is never counted
as an ordinary successful semantic match. The current live corpus contains 28
protected records total, 27 of which participate in retrieval; the additional
record is an adversarial untrusted-memory fixture added only after the ordinary
retrieval cases finish.

## Pi/Codex broker and adversarial gate

On 2026-08-19 the expanded real-Qwen3 gate repeated all 42 retrieval cases and
14 hard negatives, then exercised Pi and Codex concurrently against one
owner-only serialized broker. It passed:

- 19/19 natural paraphrases, 14/14 unrelated/same-person absent facts, both
  corrections/temporal histories, and the protected competing pair;
- 13 warm brokered preflights across six concurrent Pi/Codex pairs plus one
  poisoned-memory request, with one socket round trip and zero subprocesses per
  preflight;
- zero missing ambiguous/conflicting candidates and zero preflight-induced
  profile mutations, proven by logical SQLite snapshots before and after;
- escaped `<system>`-shaped poisoned memory delivered only under
  `trust=untrusted_memory_evidence`, with no mutation capability in the signed
  receipt;
- payload-free preflight/broker telemetry and compact runtime ritual status;
- 483.64 ms concurrent warm preflight p95, below the 500 ms target; and
- forced Pi/Codex semantic-gate failure with zero provider calls, zero agent
  starts, zero tool executions, a blocked write, and a still-manual degraded
  read-only availability query.

That p95 is a same-machine local measurement, not a universal latency promise.
The broker serializes callers deliberately; deployments must repeat the gate on
their own model, corpus, hardware, and concurrency level.

## Reproduce

```bash
ollama pull qwen3-embedding:latest
ollama stop qwen3-embedding:latest
uv run --locked python scripts/quality_benchmark.py
uv run --locked python scripts/memory_core_benchmark.py
```

The OpenClaw comparison creates an isolated temporary agent, indexes the same
records, runs the cases, and removes the agent in a `finally` block.

## The next evidence bar

Before making broad comparative claims, run independent standardized suites
such as [LongMemEval](https://arxiv.org/abs/2410.10813) and LoCoMo, publish the
exact model/hardware/configuration, and report retrieval and end-to-end answer
quality separately. Real deployment qualification should add the authorized
application corpus, multilingual queries, adversarial near-misses, larger
corpora, concurrent writers, and long-duration lifecycle behavior.

## v0.7.0 CI and release qualification

The 2026-07-25 release gate added repository-hosted CI for Python 3.10-3.14,
every bundled agent adapter, Rust ZKP, the Cloudflare gateway, the product
site, OpenTofu and Bicep templates, the confidential-origin image, CodeQL,
secret history, dependency review, and scheduled dependency audits. Every
GitHub Action is bound to a full commit SHA with read-only default
permissions.

Local release qualification passed:

- 479 Python tests plus Ruff formatting/lint and mypy;
- 5 Rust tests plus rustfmt and Clippy;
- 14 OpenClaw, 10 Pi, 9 OpenCode, 16 Hermes, 8 Worker, and 3 product-site
  tests;
- npm high-severity audits for OpenClaw, OpenCode, Pi, the Worker, and the
  site, plus pip-audit, Bandit, and cargo-audit;
- repository security, privacy/history, release-metadata, OpenTofu, and both
  Azure Bicep gates;
- twice-reproducible wheel, sdist, and OpenClaw archives, with clean wheel
  installation and Twine validation.

The release lock binds the reproducible wheel SHA-256
`93e63fa45343927bf426aeaa0da0f63bc8c4e25b52ece365c4090ac964b6733d`,
OpenClaw archive SHA-256
`0f765e5f3199e34f5cdc52a1e37de4749341b1c16cb8cf31d9896f614de614f0`,
and generated entrypoint SHA-256
`b8268ffcc423d3fce70616571e827d3d2b0fd64c647276a0e5b911a4595af578`.
The installed OpenClaw 2026.7.1-2 boundary then passed with 9/9 tools, 3/3
protected hooks, exact artifact binding, and all records shielded.

The local Apple-Silicon Docker VM could not complete the required linux/amd64
image lane because its x86 emulator crashed inside `rustc`. Native Rust
qualification passed; the pinned amd64 image remains a required GitHub-hosted
CI result. The live deployment is still `local-staging` and reports
`production_ready=false`; neither repository CI nor local qualification proves
external enclave provisioning or independent cryptographic review.
