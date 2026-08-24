# Changelog

All notable changes to Echo Veil are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.8.0] - 2026-08-20

### Changed

- Added a digest-pinned, query-blind LongMemEval-S pilot that partitions long
  sessions into bounded contiguous capture units before storing seed crystals.
  It keeps gold-session provenance retrieval separate from answer support and
  optional non-official reader exact/F1, rejects raw-transcript persistence,
  and uses an owner-only public-benchmark cache bound to the dataset, model,
  prompt, and partition contract.
- Expanded the bounded local qualification gate with six lifecycle checkpoints
  spanning 365 simulated days and a 48-record v2-to-v3 migration under 96
  scheduled reads from four workers. The stale record demotes and evicts, the
  locked record survives, all records reconcile after restart, and the report
  explicitly keeps `preflight_v2` while disclaiming wall-clock soak and physical
  power-loss evidence.
- Added an explicit, non-default `supporting` recall mode for indirect and
  multi-hop evidence while preserving the existing `direct` answerability gate.
  Supporting results are labeled non-authoritative, confidence gating remains
  enforced, the optional operation argument is omitted by legacy consumers,
  and every preflight-v2/runtime/evidence/telemetry identifier remains frozen.
  A digest-pinned 50-question LoCoMo pilot reached 73.53% top-one and 90.20%
  recall@5 on fully captured evidence while rejecting both hard negatives; it
  is reported as retrieval-only rather than an end-to-end answer score.
- Hardened the non-mutating `init local-production` guide so it closes its
  embedding transport, reports current backup, restore, and rollback evidence,
  emits stable path-free remediation codes, and blocks the unconfigured
  external-monotonic tier. The 2026-08-20 real-Qwen gate passed all 42 retrieval
  cases and 14 hard negatives, with 223.29 ms recall p95 and 478.17 ms warm
  concurrent Pi/Codex preflight p95.
- Added six-language semantic retrieval cases and a bounded 1K/10K/100K local
  index qualification gate. Keyed projection planes are reused per stable
  dimension, SQLite accepts atomic 1,000-entry index batches, and the gate
  reports recall, exact-rerank candidate fraction, latency, storage growth,
  concurrent WAL reads/writes, and abrupt pre/post-commit recovery without
  mislabeling the latter as a physical power-cut test.
- Added a pinned N-1 compatibility gate for the exact v0.7 consumer bytes.
  CI now generates responses from real mixed-v2/v3 and fully-v3 profiles,
  executes the prior OpenClaw, OpenCode, Pi, Hermes, and shared Python
  consumers against them, rehashes the legacy artifacts after execution, and
  separately proves that the old core rejects a v3-activated profile. Storage
  v3 remains invisible to harnesses; `preflight_v2`, its v2 receipt, and the v1
  runtime/evidence/telemetry contracts retain their identifiers.
- Ordinary `echo_veil_recall` and `echo_veil_context` are lifecycle-neutral.
  Asking a question no longer advances decay, reinforcement, or twilight
  eviction. Mutation remains available only through an explicit
  `mutate_lifecycle=True` Python recall call.
- Echo Veil is the primary mutable memory store, not a veto over wiki, files,
  or other host evidence. The shared Agent Skill and Goose recipe no longer
  require stopping all work when protection is unavailable.
- Added a first-class Grok Build connector (`integrations/grok`) with MCP,
  skill, marketplace, and hooks. Grok `UserPromptSubmit` injects protected
  context and is documented as non-blocking; `PreToolUse` can deny
  unpreflighted `spawn_subagent` calls. The hook parser accepts Grok's
  camelCase envelope.

### Security

- Raised the minimum `cryptography` runtime to 50.0 after the locked 49.0.0
  release received a security advisory. Release CI now exercises the pinned
  v0.7 Python consumer inside the locked environment, supports the hosted macOS
  Swift 6.1 toolchain, scans the complete release history with a narrowly
  source-bound false-positive exception, and keeps the key-custody finalizer in
  a safe state even when constructor validation exits early.
- CI now rejects any runtime or harness-facing preflight-v3 identifier, runs the
  complete 1K/10K/100K local qualification in one dedicated job, and requires a
  successful full CI run for the exact annotated-tag commit before the release
  workflow will build artifacts.
- Serialized every same-profile AgentMemory operation so the two writer-locked
  SQLite snapshots cannot straddle a concurrent in-process mutation. Portable
  restore now requires both recovery-key authentication and an independent
  profile-root MAC/hash check after custody import; prior readiness receipts
  are retained only under inactive recovery evidence and never transfer host or
  artifact authority to the restored runtime.
- Made recovery a prerequisite for the first nonempty record-envelope v3
  activation. The exact backup-v1 manifest now authenticates either an
  envelope-v2 device-bound recovery set or an envelope-v3 readiness set without
  changing its field inventory; the serialized receipt-v1 shape also remains
  unchanged. Migration accepts only a profile-bound, freshly verified v2
  capability, rejects missing, cross-profile, and stale-count receipts, and
  never lets pre-migration evidence satisfy v3 backup/restore readiness.
- Made the authenticated v3 key-manifest feature a one-way write-version floor.
  Record-envelope state now rejects impossible prepared/migrating/verified
  combinations, false verification while v2 data remains, live attempts to
  restore v2 writes, and cross-profile ciphertext transplantation. Local
  readiness also counts remaining v2 lifecycle anchors rather than trusting a
  mutable migration-state label.
- Bound local-production host evidence to the actual invoking harness. A
  receipt qualified for one shared-profile caller no longer transfers host,
  backup, or restore readiness to another. Local production now blocks both
  startup and runtime embedding outages instead of entering Offline Read-Only
  Recall, and all bundled `capabilities_v1` parsers reject mutually
  contradictory local/enclave readiness claims.
- Added path-free installed-artifact and short-lived host-boundary authority
  receipts for host-trusted local production. Artifact status is re-derived
  from a retained wheel, PEP 610 hash, installed package bytes, and all Echo
  entry points; any drift invalidates the artifact, host, and authority-bound
  backup evidence. Host qualification requires a verified preflight-v2 healthy
  run, a blocked forced outage with zero provider/model/agent/tool execution,
  no competing mutable memory, and exact profile, scope, preflight, Echo, and
  host-artifact bindings. Neither receipt changes or authorizes preflight.
- Bound authenticated backup receipts to the current installed-artifact and
  qualified-host authority IDs. Manifest verification now validates the key
  epoch, model identity, scoped-v2 contract, record-envelope version, recovery
  mode, rollback tier, logical-count inventory, and optional authority digests
  before a backup can satisfy local readiness.
- File-key retirement after macOS custody migration now requires a different
  process, proven by a root-authenticated activation receipt rather than a new
  Python object. Retirement is resumable across the descriptor/file-removal
  crash window. The deterministic custody gate also advances two local
  monotonic backup generations and proves that verification and dry-run restore
  reject the stale first snapshot.

- Added internal record-envelope v3 with HKDF-SHA256 purpose separation across
  payload, vector, semantic-contract, token, digest, integrity, tombstone,
  index, preflight-key, and backup-manifest domains. Activation is explicit,
  bounded, dual-read, restart-resumable, and protected by a persistent
  downgrade barrier; unknown formats, lost keys, and cross-domain decryptions
  fail closed.
- Replaced raw stable LSH buckets with profile-keyed projection families,
  HMAC-SHA256 bucket tokens, and record/band authentication tags under an
  independently versioned index contract.
  Schema 1-3 stores rebuild into schema 4, key/envelope rotation rekeys the
  index, and integrity checks reject copied or altered buckets while continuing
  to disclose equality, access-pattern, and approximate-neighborhood leakage.
- Hardened POSIX key, manifest, profile, database, and SQLite-sidecar access with
  UID validation, pinned no-follow ancestry, descriptor-relative opens,
  single-link enforcement, atomic descriptor-relative publication, and
  post-open inode revalidation. Unsafe writable ancestors, hard links,
  symlinks, and namespace replacement now fail closed instead of being repaired.

- Isolated Codex profiles now disable the plugin loader, account-level apps,
  the independently enabled remote plugin catalog, and app-backed MCP
  connectors while applying an all-connectors-denied policy. The launcher
  installs only the receipt-bound Echo hook and skill assets directly, so an
  authenticated account cannot silently widen the Echo-only interactive tool
  boundary.

- Made Windows local-memory publication fail closed: key manifests now use
  private-at-creation native staging, binary fsync, same-volume write-through
  replacement, pinned namespace ancestry, and exact post-publication
  byte/path/type/link/DACL verification. Raw keys, SQLite databases, profile
  directories, and inherited SQLite sidecars now use the same protected
  current-user/System at-rest boundary instead of relying on ignored POSIX mode
  bits. Standalone SQLite stores create missing dedicated parents privately and
  reject broad existing parents without rewriting caller-owned directory DACLs.
  Persisted raw keys are reopened with binary, non-inheritable Windows CRT
  descriptors so key bytes cannot be changed or truncated by text translation.
- Replaced signed configuration-only enclave claims with native Azure
  attestation verification bound to the nonce, ephemeral transport key,
  workload digest, CCE/MAA policy, issuer/JWKS, launch measurement, and
  non-debuggable/non-migratable SEV-SNP state.
- Bound CKKS ciphertext wrappers and sessions to verified identity, profile,
  scope, key fingerprint, dimension, version, and authenticated metadata;
  rejected Ristretto identity public keys and added cross-client/tamper/replay
  regressions.
- Authenticated lifecycle, supersession, operation, vector-row, keyed-term, and
  tombstone metadata, and added monotonic profile generation/CAS protection for
  stale simultaneous writers.

### Added

- Added the RPC-only `capabilities_v1` readiness surface and a distinct,
  fail-closed `local-production` mode. Host-trusted local readiness now requires
  independent artifact, Secure Enclave custody, backup, restore, host-boundary,
  digest-bound Qwen3, profile-access, migration, and protected-state evidence;
  the current file-key profile remains local staging. The signed preflight-v2
  response and receipt are unchanged.
- Added an authoritative protocol registry and shared Python/TypeScript/
  JavaScript fixtures that freeze signed preflight v2, retain the unsigned
  preflight bridge, expose `capabilities_v1` independently, and keep the now
  implemented record-envelope v3 invisible to harness consumers.
- Added signed lifecycle-neutral `preflight_v2` receipts with exact
  query/session/turn/model/tool/artifact bindings, one-use replay defense,
  adaptive one-or-two-result evidence, compact ritual status, multilingual
  causal intent routing, conservative token budgets, and payload-free stage
  telemetry.
- Added an owner-only serialized Unix-domain broker for warm Pi/Codex access.
  It enforces bounded frames, same-user/socket permissions, sequential dispatch,
  generic errors, payload-free transport telemetry, and fail-closed brokered
  MCP startup.
- Added receipt-bound Pi `0.84.2` and Codex `0.147.0` isolated boundaries. Pi
  verifies the receipt at its provider boundary with sequential tools and
  one-use consent; Codex binds its executable, wheel, entry points,
  plugin/hooks/MCP, model, configuration, and optional broker authority.

### Changed

- Fixed Contextual Logic evidence budgeting so linked records no longer mutate
  or enlarge the signed recall candidate list.
- Kept degraded Always-Available retrieval manual, read-only, visibly
  non-semantic, mutation-disabled, and incapable of authorizing a required
  model turn.
- Explicitly disqualified direct Codex collaboration because children inherit
  root context without a task-specific receipt, and downgraded direct Codex
  singular-authority claims when competing mutable-memory plugins are exposed.
- Expanded the real Qwen3 quality gate with concurrent Pi/Codex broker calls,
  poisoned memories, forced outages, profile mutation snapshots, and a warm
  p95 target below 500 ms. The 2026-08-19 run passed at 483.64 ms with zero
  lost competing candidates, zero unrequested mutations, and zero
  provider/agent/tool activity during required-gate failure.

## [0.7.0] - 2026-07-25

### Added

- Added a complete CI and supply-chain gate across Python 3.10-3.14, every
  bundled agent adapter, Rust ZKP, the Cloudflare gateway, the product site,
  OpenTofu/Bicep infrastructure, the confidential-origin container, CodeQL,
  secret history, dependency review, and scheduled dependency audits.
- Added twice-reproducible Python and OpenClaw package checks. The reviewed
  deployment lock now carries a fixed build epoch and binds the exact wheel,
  plugin archive, and generated entrypoint included in the release candidate.
- Added a payload-silent host-authority evidence manifest and verifier that
  binds each qualified boundary to exact Echo source digests and tested host
  versions, fails CI on source drift, and keeps conditional, externally
  unbound, repository-only, stale, and blocked states explicit.
- Added strict AIP artifact receipts to the host-authority verifier. The
  installed runtime must match one reviewed wheel SHA-256 through PEP 610,
  verify every installed Python source against its wheel `RECORD`, and retain
  the exact memory contract, profile, scope, caller, and no-plaintext-fallback
  binding.
- Added a payload-silent OpenClaw deployment lock and live verifier. It rejects
  missing agent tools or protected hooks, native or stale memory authorities,
  mutable checkout loading, artifact or installed-source drift, unsafe gateway
  settings, non-owner-only profile paths, doctor integrity failures, and
  production claims made from local staging.
- Required OpenClaw's Echo memory slot, both protected hook permissions, and
  explicitly disabled native `session-memory` before its pre-model gate will
  pass; required Claude Code's official auto-memory disable control before its
  preflight opens Echo, and documented native-memory shutdown for Codex
  singular authority.
- Added distinct Live, Short-Term, Long-Term, and Contextual Logic roles to the
  shared agent-memory contract, with bounded Live expiry, Short-Term review
  guidance, explicit ordered promotion evidence, typed logic relationships,
  and per-result provenance plus promotion/archive recommendations.
- Added `echo_veil_promote` to the common MCP/RPC contract and the native
  OpenClaw and Pi adapters.
- Added `echo_veil_refresh_live` across the common MCP/RPC contract and native
  adapters. Unchanged state renews its protected contract; changed state creates
  an explicit shielded superseding version.
- Added optional semantic-layer scopes to recall without score rewriting, plus
  `echo_veil_context` for a depth/record/edge-bounded trace from at most two
  confidence-checked logic roots to independently authenticated outgoing
  evidence.
- Added bounded competing-memory groups that keep the strongest authenticated
  same-topic current pair together, preserve each member's provenance and
  confidence, and recommend explicit supersession or protected Contextual Logic
  without inventing semantic incompatibility or a winner.
- Added a generalized, explicitly confirmed profile migration command that
  re-embeds compatible legacy or scoped profiles into a fresh scoped Qwen3
  target without creating a plaintext export.
- Added a read-only profile-migration verifier that proves content,
  effective-time, supersession-edge, protected-contract, and retrieval-index
  equivalence through process-local HMAC tokens without emitting payloads or
  stable record fingerprints.
- Added a dry-run-first host-catalog migration command with payload-silent risk
  review, exact import and retirement confirmations, protected Short-Term
  provenance, retry deduplication, separate-process verification, hash-only
  receipts, and source retention on failure.
- Added `echo_veil_list`, a bounded, lifecycle-neutral administrative inventory
  operation, across the common RPC/MCP contract and native OpenClaw/Pi adapters.
- Added AIP as a required fresh-process Echo consumer with no plaintext runtime
  fallback, four-layer lifecycle tools, caller-bound provenance, and an
  explicit dry-run-first legacy markdown rehydration path.
- Added one implicit `echo-veil-memory` Agent Skill for Codex and Claude Code,
  plus an OpenClaw memory-capability prompt builder and an Algo CLI runtime
  contract for doctor-backed recall, Contextual Logic, disciplined writes, and
  fail-closed host behavior.
- Added the same canonical fail-closed memory skill to Hermes so its live MCP
  tools follow the shared preflight, minimal-recall, reasoning, and write
  discipline instead of relying on tool discovery alone.
- Added a Hermes 0.18.2 native plugin that pairs ephemeral `pre_llm_call`
  protected context with an exact session/task/turn plus per-request nonce
  `llm_execution` gate.
  Failed, malformed, oversized, timed-out, or semantically unavailable
  preflight now returns a zero-usage blocked response without invoking the
  provider; protected hook context stays below Hermes's disk-spill threshold.
- Added a shield-owned Hermes headless path that validates the plugin by
  build-bound digest, isolates `HERMES_HOME`, disables both native memories,
  binds the turn to a launch nonce, and requests a plugin-defined command
  registered only after the required hook and middleware. It uses one
  loopback provider and the Echo-only MCP toolset so plugin registration
  failure cannot fall through to an unprotected one-shot.
- Packaged that canonical skill with Pi, OpenCode, and Droid so every
  skill-capable full adapter exposes the same behavioral authority.
- Added an OpenCode plugin that performs protected semantic recall at
  `chat.message`, requires a matching message preflight at `chat.params`,
  preflights supported `Task` prompts, disables unbound automatic
  post-compaction continuation, and passes only a fixed child argument vector
  plus an explicit environment allowlist. Added a dependency-free npm lockfile
  so clean-install and audit gates are reproducible instead of being skipped.
- Added an enforced Pi runtime preflight that validates the protected profile,
  recalls at least two candidates before every model turn, traces Contextual
  Logic for causal prompts, rechecks expanded skill/template prompts, bounds
  and escapes untrusted memory evidence, blocks mid-run bypasses, denies tools
  outside the authorized run, and aborts an agent start without preflight.
- Added one shared fail-closed Python root-turn and `PreToolUse(Agent)` hook for
  Codex and Claude Code. It validates scoped-v2/Qwen3 readiness, performs
  two-slot non-inferential recall plus bounded causal Contextual Logic, escapes
  hostile memory as untrusted JSON, omits rather than truncates oversized
  payloads, rewrites supported subagent task input only after protected recall,
  and returns a payload-silent structured stop or Agent-tool denial on every
  failure.
- Added deny-only, child-specific qualification controls for Codex/Claude
  `Agent` and OpenCode `Task` smokes. They leave root preflight healthy while
  proving the child boundary stops before opening Echo or starting a child
  model, and cannot authorize or redirect execution.
- Expanded the Codex spawn matcher and bounded hook parser to cover the current
  `spawn_agent` and `collaboration.spawn_agent` tool identities in addition to
  the documented `Agent` alias. Installed Codex collaboration still bypasses
  `PreToolUse`, so those parser tests are not presented as a host gate.
- Added local marketplace descriptors for the complete Codex and Claude Code
  plugins. Both bundles now use installed, path-independent
  `echo-veil-agent` and `echo-veil-preflight-hook` entry points.
- Added packaged Droid root-turn and `PreToolUse(Task)` hook definitions through
  a fixed wrapper that accepts only an absolute executable and uses Droid's
  blocking exit status. The hook has no host timeout because Droid treats hook
  timeouts as non-blocking failures.
- Added `echo-veil-shielded-run` for fail-closed headless Codex, Droid, and
  Goose turns. It preflights before host creation, transports prompt/context
  only through child stdin, and strips unrelated environment variables. Codex
  ignores ambient user config, receives one required Echo MCP server, disables
  native memory, Chronicle, goals, plugins, and parallel agents, starts
  ephemeral, and defaults to a read-only sandbox. It creates an owner-only
  temporary Codex home that links only the validated auth file, preventing
  global skills, model cache, goals, and session state from leaking into the
  child. Goose suppresses its default
  profile/session; Droid disables `Task` because its installed `exec` path
  cannot prove child-specific preflight.
- Added a three-stage OpenClaw gate that claims the request early, injects
  protected context with a random expiring attestation, and consumes that
  attestation once at the pre-model boundary.
- Added a concurrent shared-authority conformance gate in which every full
  tool-host caller writes to one scoped profile and recalls another caller's
  protected record without losing provenance.

### Changed

- Required Long-Term memories to pass through explicit Short-Term promotion
  instead of allowing direct writes.
- Made source erasure transitively delete dependent Contextual Logic records,
  and made the read-only availability layer authenticate the same semantic
  contract without mutating it. Degraded context traces use the same
  conservative keyed-root and protected-link boundary.
- Restricted legacy-v1 profiles to explicit migration workflows because their
  plaintext topic metadata cannot satisfy the four-layer shield contract.
- Made direct semantic and read-only availability calls expand `top_k=1` only
  when required to preserve an authenticated competing pair.
- Enforced a bounded seed-crystal policy with per-layer character limits,
  transcript-shaped content restricted to Live, no automatic rewriting, and
  explicit durable provenance required for Long-Term promotion.
- Bound bundled adapters to the versioned `echo-universal-qwen3-v1` profile and
  explicit `local-user` authorization scope for same-user harnesses, while
  retaining distinct-profile guidance for different users and trust
  boundaries.
- Bound every full bundled host transport to a stable `caller:<host>`
  provenance marker, while reserving separate non-caller evidence for
  Long-Term promotion and Contextual Logic. Added the Algo CLI in-process
  bridge to the supported-host integration matrix.
- Changed long-lived MCP transports to validate and release their startup probe,
  then open and close the shared profile per tool call. Algo CLI does the same
  per memory operation. Profile migration still requires doctor inspection and
  an explicit fresh target; non-empty sources are never silently merged.
- Made AIP omit its state-directory override by default so the canonical
  profile resolves to Echo Veil's shared user data root. An explicit AIP
  `state_dir` now means deliberate isolation rather than an accidental second
  memory universe.
- Made AIP preserve authenticated records from other harnesses under an
  explicit `shared` domain instead of discarding every topic outside AIP's own
  metadata convention.
- Moved AIP's required semantic preflight into a common provider wrapper so
  runtime Agent, SDK, workflow, chat, streaming, and vision generation share
  one fail-closed boundary. Discovery, health, embedding, and model lifecycle
  calls remain non-generative delegated operations.
- Converted OpenClaw from an additive tool plugin to the selected exclusive
  memory slot while preserving all nine native tools and legacy provider data
  as non-authoritative migration evidence.
- Required protected OpenClaw model routes to use
  `agentRuntime.id="openclaw"` because its native Codex app-server path does not
  invoke the complete early-reply/pre-model hook pair.

### Security

- Added weekly Dependabot coverage for the OpenClaw, OpenCode, and Pi adapters;
  high-severity npm audits now cover all three alongside the Worker and site.
  Release candidates include the locked OpenClaw archive, SBOM, checksums, and
  GitHub provenance attestation behind the protected release environment.
- Qualified the installed AIP 0.1.1 boundary only after a reproducible,
  hash-fragment-installed wheel passed its payload-silent artifact receipt,
  healthy protected inference, and forced semantic-outage zero-provider-call
  smoke. Editable, unhashed, mismatched, tampered, or permissively writable
  installations remain unqualified.

- Reduced the default MCP surface to the nine agent-memory operations. Key
  rotation and previous-key retirement are hidden and rejected unless a
  separately reviewed operator server explicitly enables `--operator-tools`.
- Encrypted layer identity, provenance, retention timestamps, complete
  promotion history, logic kind, and related record IDs in a record/scope/
  schema/key-bound AES-GCM contract committed with every scoped-v2 payload.
- Bound a four-layer-required feature marker into the profile key manifest so
  deleting both the database schema marker and all contract rows cannot trigger
  a silent default-layer downgrade.
- Added fail-closed missing/tampered-contract, plaintext-leakage,
  promotion-order, restart, expiry, relationship-integrity, and cascade-erasure
  coverage. Context tests additionally cover root gating, ambiguity, bounds,
  linked-contract tampering, historical validity, and the degraded read-only
  path. Contract ciphertext participates in resumable key rotation.
- Recompute and authenticate each selected opaque topic token against its
  encrypted record before using topic equality for ambiguity or possible-
  conflict signaling; copied tokens quarantine instead of creating false
  groups.
- Added fail-closed coverage for seed-crystal bounds, transcript escape,
  protected Live renewal/supersession, restart persistence, stale-version
  refresh, and degraded-mode write rejection.
- Required protected harness integrations to reject incomplete four-layer
  readiness, bypass legacy plaintext memory recall, and label degraded
  keyed-only results without presenting them as semantic or authoritative.
- Added a parameterized cross-host conformance gate that exercises Live
  refresh, ordered Long-Term promotion, Contextual Logic tracing, layer-scoped
  recall, and caller-bound provenance for every full tool host.
- Made exact-retry deduplication compare UTF-8 bytes so non-ASCII protected
  topics and payloads remain idempotent across every harness.
- Added owner, mode, symlink, size, record-count, transcript, content-risk,
  rollback-under-lease, and verified-retirement checks for host-catalog
  migration.
- Replaced the website's vulnerable transitive ESLint preset graph with a
  smaller ESLint 10, TypeScript-ESLint, and direct Next ruleset; pinned the
  patched brace expansion implementation and retained explicit raw-HTML and
  dynamic-execution bans. The clean install now audits with zero findings.
- Added isolated real-loader validation proving OpenClaw selects Echo Veil as
  its memory slot, loads the exact nine-tool contract, and reports no plugin
  diagnostics. Required Algo prompts now stop before model execution when
  protected recall fails instead of proceeding with legacy context.
- Qualified Pi's native gate in isolated 0.82.0 RPC processes: protected
  Qwen3/Contextual Logic preflight completed without a model call, an Echo
  outage stopped ordinary input before agent start, and a custom trigger that
  bypassed input hooks was aborted with zero model tokens.
- Qualified installed local-marketplace root hooks against Claude Code 2.1.207
  and Codex 0.144.5. Simulated Ollama outages stopped both before provider
  execution with zero model tokens; Claude additionally reported zero turns,
  API duration, and cost. Codex required explicit `/hooks` review of both exact
  hashes; before that review, the installed hook was correctly treated as
  untrusted and did not gate the model. Installed child-tool evidence remains
  separate from those root-turn qualifications.
- Excluded direct Codex collaboration after a child-only deny run still reached
  the 0.144.5 router without invoking `PreToolUse`. Qualified the separate
  shield-owned Codex headless path with a healthy ephemeral read-only turn and
  a forced semantic outage that returned before Codex startup. The launcher
  disables the unhookable subagent paths instead of claiming to protect them.
- Qualified OpenClaw 2026.7.1-2 in its pinned OpenClaw runtime with Echo as the
  selected memory slot and all three hooks loaded. A forced outage returned a
  hook block before model startup. The native Codex app-server path was tested
  and excluded from the hard-gate claim.
- Qualified Algo CLI required mode with its installed Echo profile, focused
  bridge/pipeline/harness tests, and a counted disabled-Echo probe that stopped
  with zero model rounds, generated tokens, or `/api/chat` requests. Its
  explicitly degraded read-only Ollama-outage behavior remains distinct from a
  required-authority outage.
- Qualified OpenCode 1.17.18 through its normal global-plugin path: a healthy
  turn stored the protected Echo marker, while the deny-only outage control
  produced zero assistant messages, tokens, and cost. Retained isolated
  OpenCode/Droid MCP loading and OpenCode skill discovery evidence. Hardened
  the Goose recipe after live 1.41.0 testing showed that `--no-profile`
  suppresses recipe extensions; startup now executes doctor plus two-slot,
  non-inferential recall in the real extension and stops cleanly when its Echo
  tools are absent.
- Found that Droid 0.170.0 `exec` bypasses both plugin and user prompt hooks;
  removed bare `droid exec` from the hard-gate claim. Qualified the separate
  shield-owned headless launcher with a healthy local turn and a forced outage
  that returned before any Droid process could start. Interactive Droid hooks
  remain separately unqualified.
- Qualified the installed Goose 1.41.0 shielded launcher with the explicit Echo
  extension, `--no-profile`, `--no-session`, both Echo-only and reviewed
  `developer` builtin healthy turns, and a forced preflight outage that returned
  before Goose startup. The normal recipe remains policy-driven.
- Requalified the installed Algo CLI required-protection runtime against the
  shared profile: 55 focused tests passed, a healthy project-cwd one-shot
  completed after protected context construction, and an isolated disabled-Echo
  run stopped with zero rounds, tokens, or tool calls. Retained a separate
  220.5-second interrupted large-model/default-cwd run as a QoS measurement
  gap rather than counting it as success.
- Marked Mercury explicitly incompatible with singular-authority mode:
  disabling Second Brain falls back to native Long-Term search while its
  Short-Term and Episodic stores remain active. Its bundled skill remains
  payload-silent and doctor-only until an upstream structured backend can
  suppress every competing mutable memory path.

## [0.6.0] - 2026-07-24

### Changed

- Upgraded new local agent profiles to a scoped-v2 security format that
  encrypts topics with payloads, protects retrieval vectors, minimizes lexical
  metadata with keyed hashes, and binds every encrypted object to its
  scope/record/schema/key identity.
- Reordered scoped-v2 remember into a recoverable pending-payload → durable
  lifecycle → commit protocol with stable record IDs and startup
  reconciliation; unexplained committed orphans remain operator-visible.
- Serialized each writable local adapter profile with an owner-only SQLite
  lease, added bounded lock-wait configuration, and reconciled interrupted
  lifecycle-first writes before a profile becomes available.
- Revalidated mutable Ollama model tags before every embedding batch so a
  long-lived adapter cannot silently continue after the resolved artifact or
  maximum dimension changes.
- Allowed long-lived CLI/MCP processes to transition from semantic recall to
  the explicit read-only availability layer when an Ollama outage begins after
  startup; identity and malformed-response failures remain hard stops.
- Added strict schema-version, schema-object, foreign-key, and integrity checks
  to the local lifecycle and encrypted payload databases.

### Security

- Replaced raw-key profile metadata with an owner-only key-reference manifest,
  added resumable multi-key rotation and separately confirmed retirement, and
  authenticated deletion tombstones.
- Added nonce uniqueness constraints, cross-table reuse detection, scope
  binding, record-level corruption quarantine, lost-key hard failure, opaque
  diagnostics, and granular local readiness reporting.
- Rejected duplicate JSON keys, non-finite numbers, unknown protocol fields,
  malformed JSON-RPC envelopes, non-canonical base64, and oversized encrypted
  records across the adapter, gateway client, attestation, origin, and CKKS
  boundaries.
- Bounded proof-helper input/output and trust files, withheld unrelated host
  credentials from Python, OpenClaw, and Pi child processes, discarded child
  stderr, and added timeout termination escalation without enabling a shell.
- Refused Cloudflare and origin redirects that could forward Access, bearer, or
  mTLS credentials; tightened origin-token and team-domain validation; and
  prevented unauthenticated envelopes from consuming replay-cache capacity.
- Rejected symlinked state/secret paths, incomplete or permissive CKKS key
  state, unexpected SQLite triggers, and attestation signer/config/transport-key
  mismatches.
- Added CSP, HSTS, framing, MIME, referrer, and browser-permission policy to the
  product Worker and limited the public brochure endpoint to GET and HEAD.
- Allowlisted the enclave container build context, normalized source ownership
  and permissions for its non-root runtime, and pinned patched Cloudflare/site
  transitive dependencies so high-severity dependency audits pass.
- Added the tracked OpenClaw distribution to deterministic security scanning,
  release-file validation, and a CI rebuild/no-diff gate.

## [0.5.0] - 2026-07-21

### Changed

- Switched bundled full agent adapters to versioned local
  `qwen3-embedding:latest` profiles with instruction-aware queries,
  1,024-dimensional output, a calibrated `0.44` broad-recall threshold, and a
  separate `0.42` predicate-answerability threshold.
- Persisted model digest, dimension, and query-instruction identity per profile
  so hashing, model updates, and incompatible dimensions cannot mix silently.
- Replaced single-vector adapter retrieval with AES-GCM-protected passage
  vectors, MaxSim scoring, keyed lexical matching, and topic-aware MMR.
- Added explicit fact supersession and point-in-time recall while preserving
  corrected and conflicting history.

### Added

- Added a loopback-only, bounded Ollama embedding client and a neutral semantic
  qualification covering keyword recall, paraphrase recall, and distractor
  rejection.
- Added a 42-query quality gate with long-memory, correction, temporal, restart,
  cold-start, latency, and distractor coverage plus a same-corpus memory-core
  comparison harness.
- Added confirmed protected reindexing and an in-process hashing-to-Qwen profile
  migration that creates no plaintext export.
- Added a subject-masked semantic answerability gate, batched broad/predicate
  Ollama queries, per-result answerability diagnostics, and same-subject
  absent-fact regression cases.
- Added an encrypted read-only always-available recall layer for local Ollama
  service/model outages, with conservative keyed predicate matching, explicit
  degraded telemetry, disabled mutations, and outage coverage in the quality
  gate.
- Added ranking margin and ambiguity telemetry so close, relevant top results
  remain visible instead of being forced through corpus-specific reranking.
- Enforced two-candidate preservation at agent RPC/MCP boundaries, documented
  degraded recall as non-semantic and non-authoritative in every full adapter,
  and added OpenClaw fresh-process RPC latency telemetry.

## [0.4.0] - 2026-07-20

### Changed

- Added a keyboard skip link, visible focus states, canonical metadata, and a
  non-repeating screen-reader description to the product site.
- Added deterministic gateway unit tests and sanitized, status-aware Python
  gateway errors for easier integration troubleshooting.
- Added Wrangler-generated binding drift checks, request IDs, structured safe
  failure telemetry, endpoint response validation, and sampled Worker tracing.
- Added direct source and integration-guide links to the product site.
- Replaced project-specific names in public examples with neutral fixtures.

### Added

- Added a durable local `AgentMemory` adapter with stable hashing embeddings,
  AES-GCM protected vectors, encrypted payload storage, deduplication, and
  confidence-gated active/cold recall.
- Added a dependency-free stdio MCP server and Codex/Claude Code plugin bundles.
- Added a native OpenClaw tool plugin with remember, recall, forget, and doctor
  operations backed by the same Python adapter.
- Added Hermes, OpenCode, Droid, and Goose MCP configurations plus a native Pi
  extension with locked, vulnerability-audited development dependencies.
- Added a guarded Mercury Agent Skill that exposes readiness without leaking
  protected content through its shell-only public extension boundary.
- Isolated every host in its own default profile and removed local filesystem
  paths from the model-visible doctor report.
- Added `Oracle.forget()` for fail-closed deletion across Echo Veil-managed
  L1/L2/L3 state, including atomic SQLite rollback and best-effort
  live-material release.
- Durable transactional SQLite storage for the L1/L2/L3 memory tiers.
- Indexed approximate retrieval with exact shield-aware reranking.
- AES-GCM protection for development and staging deployments.
- An attested enclave protocol with an OpenFHE CKKS origin implementation.
- A Ristretto255 Schnorr proof-of-possession access gate.
- Cloudflare Access, Worker, mTLS, and OpenTofu deployment configuration.
- Azure SEV-SNP confidential VM and Key Vault Secure Key Release templates.
- Release, supply-chain, static-analysis, and dependency security gates.
- Repository-agent instructions, an application-agent integration guide, and a
  tested executable memory adapter.
- A responsive Echo Veil product site with system visuals, use cases, stack
  placement, and a Cloudflare custom-domain deployment.

### Fixed

- Twilight vines are now rescored and automatically reinforced when the user
  returns to their topic before eviction.
- Updated the website's locked `brace-expansion` transitive dependencies to
  patched versions after a high-severity denial-of-service advisory.
- Removed the OpenClaw host runtime from the plugin's development lockfile after
  its published shrinkwrap introduced a vulnerable transitive parser; OpenClaw
  remains a peer and the real CLI is still required for release validation.

### Security

- Enforced request and response limits while streaming at both the Cloudflare
  gateway and enclave origin, rather than after unbounded buffering.
- Added a deadline to authenticated health forwarding, bounded Access JWTs,
  stricter Cloudflare team-domain validation, and defensive API headers.
- Removed upstream response bodies from Python client exceptions so enclave or
  proxy details cannot be copied into application logs.
- Production startup requires the enclave shield and fails closed when
  attestation, measurement, CKKS, hardware isolation, or the ZKP gate is absent.
- Secret generation, replay controls, bounded inputs, and encrypted key-transfer
  tooling are included and tested.

[Unreleased]: https://github.com/Seabass-up/echo-veil/compare/v0.8.0...HEAD
[0.8.0]: https://github.com/Seabass-up/echo-veil/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/Seabass-up/echo-veil/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/Seabass-up/echo-veil/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/Seabass-up/echo-veil/compare/v0.3.0...v0.5.0
[0.4.0]: https://github.com/Seabass-up/echo-veil/tree/08de0b2de7d5e63c82209c9afaa54450a2aaec15
