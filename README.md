# Echo Veil

[![CI](https://github.com/Seabass-up/echo-veil/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/Seabass-up/echo-veil/actions/workflows/ci.yml)
[![Security](https://github.com/Seabass-up/echo-veil/actions/workflows/security.yml/badge.svg?branch=master)](https://github.com/Seabass-up/echo-veil/actions/workflows/security.yml)
[![CodeQL](https://github.com/Seabass-up/echo-veil/actions/workflows/codeql.yml/badge.svg?branch=master)](https://github.com/Seabass-up/echo-veil/actions/workflows/codeql.yml)

A shielded, four-layer living-memory substrate for AI agents.

**Product site:** [echo.algo-cli.com](https://echo.algo-cli.com)

Echo Veil treats an agent's working memory not as a flat store but as a managed
pool: relevant context stays "active," fading context is compressed and
eventually archived, and contradictory information is preserved as structured
tension rather than overwritten. This repository implements the core of the
Echo Veil v1.0 specification (`docs/SPEC.md`).

The agent interface distinguishes four semantic layers—Live, Short-Term,
Long-Term, and Contextual Logic—from the physical L1/L2/L3 storage tiers.
Every scoped-v2 record carries a record-bound, authenticated, encrypted layer
contract under the same profile shield as its payload and vectors. The
contract contains provenance, expiry/review state, complete promotion evidence,
and typed contextual relationships. Missing or unauthenticated contracts stop
the profile; there is no plaintext layer fallback.

> **Status: 0.7.0 — four-layer protected memory with fail-closed host gates.**
> The memory lifecycle, conflict handling, drift detection, capability reporting,
> confidence-gating surfaces, and a practical AES-GCM Crypto Shield are implemented
> and tested. The repository includes an Azure SEV-SNP origin using OpenFHE CKKS,
> a Ristretto255 proof gate, Cloudflare Access/Worker configuration, and fail-closed
> attestation/session integration. Cloud credentials and hardware deployment are
> still required before these claims are active. See
> `docs/ARCHITECTURE_NOTES.md`.

## What's in the box

| Spec section | Module | Status |
|---|---|---|
| 1. Tiered storage | `archive.py`, `persistence.py`, `workspace.py` | In-memory reference + durable transactional SQLite L1/L2/L3 |
| 2. Workspace metabolism / decay loop | `workspace.py`, `proximity.py`, `vine.py` | Implemented |
| 3. Confidence spectrum matrix | `confidence.py` | Implemented |
| 3. Conflict / fossil / resurrection | `conflict.py` | Implemented |
| 4. Intent drift detection | `drift.py` | Implemented |
| 4. Caretaker / Gardener's Report | `caretaker.py` | Implemented |
| Four semantic memory layers | `memory_layers.py`, `agent_memory.py` | Shielded contract, expiry, promotion, provenance, and contextual links implemented |
| Practical Crypto Shield | `crypto_shield.py` | AES-256-GCM protected vectors implemented |
| 5. Level-5 cryptographic root shield | `crypto_shield.py`, `echo_veil_origin`, `crates/echo-veil-zkp` | OpenFHE CKKS origin, SEV-SNP deployment, attestation, and Ristretto proof gate implemented |
| Defensive readiness / doctor report | `capability.py`, `oracle.py` | Implemented |
| — Facade | `oracle.py` | Implemented |

## Install

```bash
pip install -e ".[dev]"
```

## Agent runtime adapters

Echo Veil includes one local encrypted host adapter used across supported runtimes. It
provides nine core operations—remember, protected Live refresh, promote,
recall, protected context tracing, bounded inventory, forget, doctor, and
protected retrieval reindexing—plus stdio
maintenance operations for resumable key rotation and explicit old-key
retirement. New scoped-v2 profiles bind each
protected object to its authorization scope, record, schema, and key; encrypt
topics, retrieval vectors, and semantic-layer contracts; use keyed opaque index
terms; reconcile
interrupted writes; authenticate tombstones; and quarantine corrupt records
without serving unauthenticated content. The
bundled host configurations use the locally installed
`qwen3-embedding:latest` model through loopback-only Ollama, 1,024-dimensional
MRL output, AES-GCM protected anchors, an encrypted payload sidecar, durable
SQLite lifecycle state, and Echo Veil's confidence gate. It does not silently
capture conversations or download a model at runtime.

New memories start in Live, Short-Term, or Contextual Logic. Live records have
a hard maximum 24-hour expiry and are deleted rather than archived when they
expire. Long-Term cannot be written directly: callers must use
`echo_veil_promote`, preserving an ordered, shielded evidence chain. Contextual
Logic requires typed links to existing records; erasing a source cascades to
dependent logic records so derived content does not outlive its source.
Recall may be scoped to any explicit subset of the four semantic layers without
changing candidate scores. `echo_veil_context` first recalls at most two
confidence-checked Contextual Logic roots, then follows only their authenticated
outgoing links with hard depth, record, and edge limits. Linked evidence is
labelled as not independently query-scored, and Echo Veil does not synthesize an
answer from the trace.

Echo Veil enforces compact memory shapes without rewriting what the caller
said. Live accepts at most 20,000 characters and may temporarily hold a raw
interaction while it is active. Short-Term is capped at 12,000 characters,
Contextual Logic at 4,000, and Long-Term seed crystals at 2,000; those three
durable roles reject transcript-shaped payloads. Full transcripts and source
artifacts remain in the authorized host store. Promotion stops until the caller
submits a compact intent/outcome memory, and every response reports the
content-policy result.

`echo_veil_refresh_live` is the continuous-state path. Repeating the same
content renews only the record's shielded expiry/provenance contract. Changed
content creates a new encrypted Live record with an explicit `supersedes` link,
so there is no silent overwrite and stale writers cannot refresh the old
version. The read-only availability layer exposes the persisted version chain
but rejects refreshes.

Two distinct current records under the same authenticated protected topic are
returned as a bounded `possible_conflict` group. Echo Veil places the strongest
pair together and, for direct SDK calls, expands `top_k=1` to two only when both
authenticated records form that pair. It does not claim the records are
semantically incompatible or invent a winner. Each member retains its own
layer, provenance, confidence, and temporal state; callers must preserve both,
explicitly supersede obsolete data, or store a protected Contextual Logic
`contradiction_resolution` that links the evidence.

This is a local staging boundary. Plaintext is still visible to the authorized
process and embedding service, and Echo Veil does not automatically protect
host logs, prompts, transcripts, wiki/graph stores, backups, swap, or physical
media. The complete threat model and application entry-point contract are in
[`docs/LOCAL_AGENT_SECURITY.md`](docs/LOCAL_AGENT_SECURITY.md).

Install the model before starting a bundled adapter:

```bash
ollama pull qwen3-embedding:latest
uv run --locked python scripts/quality_benchmark.py
```

The primary quality gate qualifies 42 keyword, paraphrase, update, temporal,
and long-memory queries plus 14 unrelated and same-subject/absent-fact
distractors against a neutral synthetic corpus. Semantic recall uses a second
predicate-focused answerability gate to reject records that mention the right
subject but do not contain the requested fact. The gate also measures cold
start, restart restoration, and recall latency. It is a reproducible regression
gate, not a universal recall claim.
See [`docs/QUALITY.md`](docs/QUALITY.md) for methodology and the current
same-corpus comparison. Echo Veil stores the resolved model digest, dimension,
and query-instruction identity with each profile and refuses to mix incompatible
vectors. Because `latest` is mutable, the adapter also re-resolves that identity
before every embedding batch and stops if the artifact changes during a
long-lived process.

If the configured local Ollama service or model is unavailable, the executable
adapter can open an existing profile through an always-available read-only
layer. It uses only the encrypted keyed predicate index, requires conservative
term coverage, returns `degraded=true`, and disables remember, forget, reindex,
promotion, Live refresh, inferential recall, and lifecycle mutation. It
authenticates and decrypts the same shielded layer contracts before returning
recall results or bounded context traces and never substitutes hashing vectors
or describes the result as semantic retrieval. A long-lived CLI or MCP
process makes the same one-way transition if the service becomes unavailable
during a later embedding call. Disable this path with
`--no-availability-layer` or `ECHO_VEIL_AVAILABILITY_LAYER=false`.

Agent-facing recall keeps at least two candidates so a close ranking cannot be
hidden by `top_k=1`. When `ranking_ambiguous=true`, callers must preserve both
leading records. When `competing_memory_detected=true`, callers must preserve
every returned member of each `competing_memory_groups` entry and must not infer
a resolution. A layer filter only removes out-of-scope candidates; it never
boosts a layer or rewrites confidence. Context traces preserve the same root
gates, ambiguity, and competing-memory signal. OpenClaw responses include
`host_transport.elapsed_ms` for the fresh-process RPC boundary; this operational
latency is reported separately from the in-process semantic-recall benchmark.

Profiles are stable authorization and embedding-identity boundaries. Do not
silently rename a bundled default: run `echo-veil-agent doctor` against the
existing profile first. A non-empty compatible profile can be rehydrated into
a fresh scoped Qwen3 target without a plaintext export:

```bash
uv run --locked python scripts/migrate_agent_profile.py \
  --source-profile old-profile --target-profile new-qwen3 \
  --source-embedder hashing --confirm
```

Use `--source-embedder ollama` plus the exact source model and dimension when
the source is already semantic. The source is retained for audit and rollback;
the target must be empty and receives new record IDs and lifecycle state.
After migration, prove an existing source/target pair without modifying either
profile or emitting content fingerprints:

```bash
uv run --locked python scripts/verify_agent_profile_migration.py \
  --source-profile old-profile --target-profile new-qwen3
```

Add `--allow-target-extras` only after reviewing why the target legitimately
contains newer records. The verifier decrypts one record at a time, compares
process-local HMAC tokens, effective times, supersession edges, and protected
four-layer contracts, and reports aggregate counts only.

Plaintext host catalogs are never imported automatically. Use
`scripts/migrate_host_memory.py` first without `--confirm` for a bounded,
payload-silent review. A confirmed import creates protected Short-Term records,
deduplicates exact retries, and must pass reopened-profile plus separate-process
verification. The source remains by default; its logical retirement has a
second exact confirmation and is not a physical secure-erase guarantee. See
[`integrations/algo-cli/README.md`](integrations/algo-cli/README.md) for the
Algo CLI workflow and [`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md)
for the generic contract.

Codex can run the bundled stdio MCP server directly from a checkout:

```bash
codex mcp add echo-veil -- \
  uv run --project /absolute/path/to/echo-veil --locked echo-veil-agent \
    --profile echo-universal-qwen3-v1 --scope local-user --caller codex \
    --embedder ollama \
    --embedding-model qwen3-embedding:latest --embedding-dimension 1024 mcp
```

The repository root is also a Codex plugin (`.codex-plugin/plugin.json` plus
`.mcp.json`) with a local marketplace descriptor in
`.agents/plugins/marketplace.json`. Claude Code has an equivalent local
marketplace descriptor. Both plugin bundles call the installed
`echo-veil-agent` and `echo-veil-preflight-hook` entry points, so the matching
Echo Veil distribution must be installed before either plugin is enabled.
Native or MCP adapters are included for Algo CLI, OpenClaw, Hermes, Claude
Code, Pi, OpenCode, Droid, and Goose.
The separately installed AIP 0.1.1 runtime wraps every provider created by
`build_runtime()` behind one semantic Echo preflight boundary. Direct Agent,
SDK, workflow capability, chat, streaming, and vision generation all stop
before the underlying provider when preflight is unavailable or malformed.
Its payload-silent authority receipt must also match the exact reviewed wheel
hash and installed `RECORD`; a matching version alone is insufficient.
Mercury receives a guarded Agent Skill that exposes readiness only because its
documented extension surface does not yet provide arbitrary MCP or structured
custom tools. Disabling Mercury's Second Brain is not sufficient: its native
Short-Term, Long-Term, and Episodic memory paths remain active, so Mercury is
not supported as a singular Echo Veil authority.

Codex, Claude Code, Hermes, Pi, OpenCode, and Droid receive the same
`echo-veil-memory` Agent Skill. Goose carries the equivalent policy in its
recipe instructions. OpenClaw registers the ritual through its exclusive memory
capability, and Algo CLI injects it into ordinary chat plus Agent Block prompts.
The policy requires doctor-backed protected recall before substantive work,
Contextual Logic for decision rationale, ambiguity/conflict preservation, and
no mutable plaintext fallback. Algo required mode enforces its pre-model stop in
runtime code. OpenClaw enforces an early reply claim, protected prompt
construction, and a one-use pre-model attestation when protected models are
pinned to `agentRuntime.id="openclaw"`. Pi's native extension performs the same
required recall in its input lifecycle, rechecks expanded skill/template
prompts, aborts unauthorized agent starts, and blocks tools outside the
authorized turn. Codex and Claude Code bundle a shared model-free hook for root
`UserPromptSubmit` and supported `Agent` tool input. The installed Codex
collaboration router currently bypasses its `PreToolUse` hook, so direct Codex
subagents are explicitly outside the protected claim. OpenCode uses a
global/project plugin to run recall at `chat.message`, require the matching
message at `chat.params`, and preflight supported `Task` prompts. Each validates
the scoped-v2 Qwen3 profile, recalls two candidates, traces bounded Contextual
Logic for causal prompts, and returns only escaped, size-bounded untrusted
evidence. A supported spawn is rewritten with task-specific protected context
before the child exists. Any readiness, retrieval, integrity, or output-bound
failure stops the qualified root turn or denies the spawn without exposing the
underlying error or consulting host memory.

Hermes uses a paired native plugin boundary: `pre_llm_call` prepares bounded
ephemeral Echo context and `llm_execution` admits the provider only for the
exact attested session/task/turn when its random nonce also survives into the
effective provider request. A swallowed observer-hook error therefore still
becomes a zero-usage blocked response instead of a provider call. For
singular mutable-memory mode, Hermes's built-in `MEMORY.md` and `USER.md`
writers must both be disabled.

For a fail-closed headless Hermes boundary, pipe the task to
`echo-veil-shielded-run hermes --model MODEL`. The launcher completes semantic
preflight before host creation, constructs a temporary owner-only
`HERMES_HOME` containing only the digest-bound Echo plugin and fixed
configuration, disables both native memory writers, binds the turn to a random
nonce, uses a fixed loopback Ollama provider, and exposes only the Echo MCP
toolset. The plugin registers `hermes echo-veil-run` only after its hook and
provider middleware; registration failure therefore makes the requested
command unreachable instead of falling through to an unprotected model turn.

Run `python scripts/verify_host_authority.py --installed` for the digest-bound
host evidence matrix. It never treats adapter presence or a matching executable
as proof of a live host gate. Use `--require-current HOST` only after reviewing
the exact qualified boundary, and rerun the release smokes after any source or
host-version drift.

Codex requires the current root hook to be enabled and explicitly trusted by
exact hash for direct plugin-mode root turns. For a harder headless boundary,
pipe the task to `echo-veil-shielded-run codex`; it preflights before Codex
exists, ignores ambient user configuration, injects one required Echo MCP
server, disables native memory, Chronicle, goals, plugins, and every current
parallel-agent feature, uses an ephemeral session, and defaults to a read-only
sandbox. Codex receives a temporary owner-only home containing only a link to
the existing owner-only auth file; ambient skills, model cache, goals, and
session state are not exposed. An `OPENAI_API_KEY` may supply auth when no
Codex auth file exists. `--sandbox workspace-write` and `--allow-non-git` are
explicit opt-ins.

```bash
printf '%s' 'Inspect the repository and report findings.' |
  echo-veil-shielded-run codex --cwd /absolute/path/to/repository
```

Direct Codex collaboration remains unqualified. Claude Code requires normal
plugin mode; `--safe-mode` and `--bare` disable custom hooks. Droid's native
interactive hooks require an absolute `ECHO_VEIL_PREFLIGHT_COMMAND`, but Droid
0.180.0 `exec` still bypasses them. Use `echo-veil-shielded-run droid` for the
qualified headless path; it preflights before host creation and disables
unpreflighted `Task` spawns. Goose has the equivalent
`echo-veil-shielded-run goose` headless path with an explicit Echo extension,
no default profile, and no session. Its normal recipe remains policy-driven.
OpenClaw requires both conversation and
prompt-injection hook permissions; its native Codex app-server runtime skips
the early-reply and pre-model hook pair and is not a qualified singular-memory
path. Claude `Agent` and OpenCode `Task` calls have the tested pre-execution
contract; the other host spawn paths retain only the evidence stated in the
enforcement matrix. OpenCode
`--pure` disables external plugins and is not a singular-authority path. Direct
`SubagentStart` hooks cannot block creation, so Echo does not rely on them for
enforcement. Out-of-band or future host spawn paths that bypass the documented
tool hook remain unqualified, and installed-host spawn smokes are separate
release gates. AIP enforces both required Echo backend selection and a common
pre-provider gate for every runtime model-generation path. Manually constructed
raw providers outside AIP's runtime builder remain outside that claim. Ordinary
Hermes plugin mode is hard-gated only while its opt-in plugin is visibly loaded
because Hermes has no required-plugin startup policy. The separate
shield-owned, local Echo-tools-only Hermes command removes that startup
ambiguity for its qualified one-turn boundary. See the
[host enforcement matrix](integrations/README.md) before using “fail-closed”
as a host-level claim.

The default MCP surface is the nine memory operations. It does not advertise
or accept profile-key rotation or key retirement. Those two maintenance tools
require a separately reviewed operator process started with
`--operator-tools`; the direct RPC boundary remains available for controlled
maintenance workflows.

Bundled local adapters default to the versioned
`echo-universal-qwen3-v1` profile and bind `ECHO_VEIL_SCOPE=local-user` plus
their stable host identity explicitly. Every full adapter adds
`caller:<host>` to write provenance. Caller identity
establishes transport attribution but never qualifies as the non-caller
evidence required for Long-Term or Contextual Logic. Echo protects dynamic
records written through its tools; it does not implicitly encrypt host
transcripts, skills, settings, source files, or legacy memory catalogs. A
harness that requires protected memory must route the write, refresh,
promotion, recall/context, and erasure through Echo and fail closed instead of
consulting a plaintext memory fallback.

OpenClaw uses the exclusive native memory plugin in `integrations/openclaw`:

```bash
npm --prefix integrations/openclaw ci --ignore-scripts
npm --prefix integrations/openclaw run plugin:validate
openclaw plugins install -l ./integrations/openclaw
openclaw plugins inspect echo-veil --runtime --json
openclaw plugins doctor
```

The install selects Echo Veil for OpenClaw's exclusive memory slot while
retaining prior provider data for explicit review or rollback. A hard
model-turn claim additionally requires both Echo hook permissions and
`agentRuntime.id="openclaw"` on every protected model. Re-run an outage smoke
after changing the OpenClaw runtime, plugin, or model route; memory-slot
selection by itself is not pre-model proof.

Linked development installs auto-detect the checkout. Packaged installs can set
the plugin's `projectPath` or use an installed `echo-veil-agent` executable.
The shared default is appropriate only for harnesses acting for the same local
user and authorization domain. Use a distinct profile for a different user,
trust boundary, or embedding identity. Each writable `AgentMemory` instance
acquires a profile-wide lease before loading Live L1 state. Long-lived MCP
transports open and close that instance per tool call, and Algo CLI does so per
memory operation, allowing concurrent harnesses to wait and serialize without
retaining a lifetime lease or overwriting a stale snapshot. See
[`integrations/README.md`](integrations/README.md) for the adapter
matrix and [`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md) for the
security and usage contract.

## Quick start

For a complete host-agent lifecycle, confidence-gating rules, security-mode
selection, and an executable adapter, see
[`docs/AGENT_INTEGRATION.md`](docs/AGENT_INTEGRATION.md).

```python
from pathlib import Path

import numpy as np
from echo_veil import AesGcmCryptoShield, Oracle, SQLiteStore, WorkspaceConfig

# Development/reference mode.
_ = Oracle(WorkspaceConfig(capacity=400))

# AES-GCM is an encrypted-storage baseline for development/staging. Store its
# key in a secret manager or ECHO_VEIL_CRYPTO_KEY, not source code.
shield = AesGcmCryptoShield(AesGcmCryptoShield.generate_key())
store = SQLiteStore(Path.home() / ".echo-veil-store" / "echo-veil.db")
oracle = Oracle(
    WorkspaceConfig(capacity=400),
    shield=shield,
    environment="staging",
    storage=store,
)

# Add active memories (anchor vectors come from your embedding model).
estimate = oracle.sprout(
    "estimate: Harbor project", embed("service upgrade quote")
)
oracle.sprout("schedule: school pickup", embed("school pickup at 3pm"))

# Each user turn: feed the current intent vector.
report = oracle.observe(embed("what was the labor rate on that estimate?"))
# -> off-topic vines drift toward twilight; on-topic ones stay active

print(oracle.report().as_dict())

# Defensive readiness / production-gap report.
print(oracle.capability_report().as_dict())

# Delete Echo Veil-managed L1/L2/L3 state for one vine. The host must also
# delete its authorized payload, backups, and separately managed artifacts.
oracle.forget(estimate.vine_id)

# Checkpoint WAL state and close the database during application shutdown.
store.close()
```

### Cloudflare enclave gateway

[`cloudflare/enclave-gateway`](cloudflare/enclave-gateway) contains a deployable
Worker that validates Cloudflare Access JWTs and forwards the enclave protocol
through an mTLS binding. Configure the Python provider with the Access service
token issued for that application:

```python
from pathlib import Path

from echo_veil import (
    Oracle,
    SQLiteStore,
    build_production_enclave_shield_from_env,
)

# Performs live Access authentication, fresh attestation verification,
# measurement allowlisting, Ristretto proof creation, and session opening.
shield = build_production_enclave_shield_from_env()
store = SQLiteStore(Path.home() / ".echo-veil-store" / "echo-veil.db")
oracle = Oracle(environment="production", shield=shield, storage=store)
```

`CloudflareEnclaveProvider.from_env()` reads the service token from
`CF_ACCESS_CLIENT_ID` and `CF_ACCESS_CLIENT_SECRET` so it does not need to
appear in application source.

The production factory additionally requires the base64 Ed25519 trust key in
`ECHO_VEIL_ATTESTATION_PUBLIC_KEY`, a JSON array in
`ECHO_VEIL_ALLOWED_MEASUREMENTS`, and the Ristretto helper/key variables
documented in the deployment runbook.

`RistrettoSchnorrProofProvider.from_env()` uses the compiled
`echo-veil-zkp` helper and an owner-only identity key. The included origin
service uses OpenFHE CKKS and consumes every proof challenge once.

The Worker is not treated as an enclave. The verifier must validate the
downstream SGX/SEV-SNP evidence and approved measurement; construction fails if
that evidence does not bind hardware isolation, CKKS similarity, and the ZKP
gate.

## Run the tests

```bash
pytest -q
```

Security issues should be reported privately through the process in
[SECURITY.md](SECURITY.md). Maintainer release controls, artifact verification,
SBOM generation, and provenance requirements are documented in
[docs/RELEASING.md](docs/RELEASING.md).

## Design notes worth knowing up front

- **The proximity-score formula is an assumption.** The preserved source spec
  names the score but omits its equation block. This implementation uses
  `cosine_similarity(intent, anchor) + 0.15 * exp(-hours_since_touched / 12)`,
  with a tunable time constant. See `proximity.py`.
- **Compression is real, not the quoted ratio.** The spec quotes "88%
  compression"; we compress with zlib and report the *achieved* ratio.
- **The practical crypto shield is real but scoped.** `AesGcmCryptoShield`
  encrypts and authenticates protected vectors with AES-256-GCM and decrypts
  transiently during `similarity()`. It is suitable for practical encrypted
  vector storage, but it is not homomorphic and not an enclave.
- **Production requires the Level-5 integration.** `Oracle(environment="production")`
  accepts `EnclaveCryptoShield` specifically; AES-GCM and custom readiness
  markers cannot bypass that guard. `EnclaveCryptoShield` requires an
  enclave provider, a deployment trust-root verifier, and a zero-knowledge proof
  provider. Construction rejects expired evidence, CKKS security below 128 bits,
  missing hardware isolation, a missing ZKP gate, or non-homomorphic similarity.
  The included Azure origin uses the official OpenFHE CKKS implementation and
  runs inside a deployment-provisioned SEV-SNP confidential VM.
- **Custom shields are conservative by default.** Echo Veil validates the
  `protect()` / `similarity()` contract. Protected payloads must implement
  `to_json_bytes()`; Echo Veil no longer falls back to archiving plaintext when
  a custom payload cannot be serialized. Capability reporting marks unknown
  custom shields degraded until their threat model is externally reviewed.
- **Inputs fail closed.** Stored vectors are copied, must be non-empty and
  finite, and must keep one embedding dimension per Oracle/Workspace. Invalid
  capacities, decay constants, timestamps, cycle overrides, confidence scores,
  and index limits are rejected at their boundaries.
- **Twilight return-to-topic recall works automatically.** A relevant intent
  now rescores and reinforces a compressed twilight vine before eviction;
  callers no longer need to know its hidden vine id in advance.
- **The adapter makes embedding selection explicit.** Bundled host profiles use
  local Qwen3 semantic embeddings with instruction-aware queries, protected
  multi-vector MaxSim over bounded live/LSH/lexical candidates, keyed lexical
  matching, topic-aware MMR, and explicit supersession history. The
  deterministic hashing backend remains available for offline tests and
  keyword-oriented recall, but is not presented as semantic retrieval. The
  Echo Veil core still accepts caller-owned stable embeddings and has no
  implicit network embedding dependency.
- **All four semantic layers share one shield boundary.** Layer identity,
  provenance, expiry/review state, promotion history, and Contextual Logic
  relationships are stored only inside a record-bound AES-GCM contract in
  scoped-v2 profiles. Long-Term requires explicit Short-Term promotion; missing
  or tampered contracts quarantine or block the record rather than downgrading
  to plaintext metadata. The bounded context tool retrieves logic roots through
  normal confidence gates and expands only authenticated outgoing links; it does
  not create a plaintext relationship index or assign query confidence to linked
  evidence. This is the local staging shield, not evidence that the external
  enclave is deployed.
- **Memory shape and Live refresh are fail-closed.** The adapter rejects
  over-limit content in every layer and transcript-shaped payloads outside
  bounded Live state; it never auto-summarizes source material. An unchanged
  Live refresh renews only its encrypted contract, while changed content becomes
  a separately protected superseding version. Long-Term promotion additionally
  requires explicit durable provenance.
- **Local recall has a bounded availability floor.** A pre-existing adapter
  profile can be opened read-only when Ollama or its configured model is
  unavailable. Only strong subject-masked keyed-term matches are returned;
  every response is marked degraded, semantic/answerability claims are absent,
  and all writes and lifecycle mutation remain disabled.
- **Eviction is retry-safe.** An archive/index failure leaves an evicted vine
  pending and retriable; pruning happens only after both lower-tier writes have
  succeeded. Building the L2 entry no longer restores plaintext onto an
  externally retained evicted Vine.
- **Durable storage is available without another dependency.** `SQLiteStore`
  checkpoints active L1 vines and commits each L2 index entry, L3 archive payload, and lifecycle/topic metadata
  in one crash-recoverable transaction. It enables WAL mode, full synchronous
  durability, integrity and foreign-key checks, schema-object validation,
  cross-process writer coordination, and owner-only database-file permissions.
  The host adapter additionally reconciles lifecycle records left by an
  interrupted remember operation and refuses to delete an unexplained encrypted
  payload orphan automatically. Reopening the store restores active, twilight,
  locked, and focal-crest state as well as searchable lower-tier memory.
- **SQLite retrieval is indexed.** Stable random-projection LSH signatures are
  stored in indexed SQLite buckets. Lookup selects approximate cosine-neighbor
  candidates and then applies the exact shield-aware scorer. Schema-v1 databases
  migrate automatically and backfill signatures for plaintext entries.
- **Internal operations are serialized.** Oracle, Workspace, index, archive,
  and drift mutations use reentrant locks. Returned `Vine` objects remain
  mutable, so callers should not edit them concurrently or bypass the public
  mutation methods.
- **Capability reporting is built in.** `Oracle.capability_report()` /
  `doctor_report()` returns a JSON-serializable readiness report covering crypto,
  storage, vector index, persistence, thread safety, and confidence gating.

Full rationale, deviations, and risks: `docs/ARCHITECTURE_NOTES.md`.

## License

Echo Veil is available under the [MIT License](LICENSE). Personal, academic,
and commercial use is permitted at no charge, including modification,
distribution, sublicensing, and sale, provided the copyright and license notice
are retained. The license grants permission to use the software; it does not
transfer ownership of the original Echo Veil copyright. Third-party components
remain subject to their own licenses.
