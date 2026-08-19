# Integrating Echo Veil with an application agent

Echo Veil is a memory lifecycle and retrieval-policy component. It is not an
embedding model, a language model, or a complete content database. The host
agent supplies embeddings and retains the memory payload under its own access,
retention, and deletion policy. Echo Veil returns stable vine identifiers that
the host can use as payload keys.

That paragraph describes the low-level `Oracle` API. The bundled
`AgentMemory` adapter is the complete local path: it stores the authorized
payload, retrieval vectors, and semantic contract in its scoped encrypted
profile so hosts do not need to invent a second payload store.

The runnable development example is
[`examples/agent_memory.py`](../examples/agent_memory.py).

## Ready-to-run agent adapters

`echo_veil.agent_memory.AgentMemory` implements the host responsibilities for a
single local OS user. It creates an owner-only profile directory, protects
vectors with AES-GCM, encrypts authorized payloads in a separate SQLite
database, and performs confidence-gated active/cold recall. Exact remember
retries are deduplicated. New scoped-v2 profiles encrypt topics with their
payloads, store only opaque keyed topic and lexical tokens, bind every encrypted
object to its scope/record/schema/key metadata, and support resumable key
rotation. Legacy-v1 profiles keep their original plaintext topic metadata until
they are explicitly migrated; remember, recall, list, promotion, and reindex
remain unavailable on those profiles rather than creating a partially
protected record. The local mode does not satisfy the production enclave profile. See
[`LOCAL_AGENT_SECURITY.md`](LOCAL_AGENT_SECURITY.md) for the complete boundary,
entry-point matrix, and release gate.

### Shielded semantic layers

Semantic role is separate from physical L1/L2/L3 placement. Each scoped-v2
memory has exactly one protected contract:

| Layer | Creation and retention rule |
| --- | --- |
| Live | Immediate state, at most 20,000 characters, with a 30-minute default and 24-hour maximum expiry; bounded transcript-shaped content is allowed only here, and expired records plus dependent logic are deleted rather than archived. |
| Short-Term | Default provisional memory, at most 12,000 characters, with a seven-day review recommendation; transcript-shaped payloads are rejected. |
| Long-Term | A compact seed crystal of at most 2,000 characters; cannot be created directly and requires explicit durable provenance when promoted from Short-Term. |
| Contextual Logic | A compact typed decision, principle, causal chain, or contradiction resolution of at most 4,000 characters, linked to existing record IDs with explicit provenance and derivation evidence; transcript-shaped payloads are rejected. |

The contract encrypts layer identity, provenance, expiry/review timestamps,
ordered promotion history, logic kind, and related IDs under the same scoped
AES-GCM keyring used for payloads and vectors. Contract ciphertext is bound to
the record, authorization scope, schema, and key. Missing, moved, corrupted, or
wrong-scope contracts fail closed. Exact duplicate writes return the existing
contract and never silently change its layer.

The content policy is deterministic and fail-closed. Echo Veil does not ask a
model to summarize, does not silently truncate, and does not transform raw
source material into a memory. The authorized host keeps full transcripts and
artifacts, then supplies a compact statement of intent, evidence, and outcome.
Every authorized result includes `content_policy`, including whether compaction
is required before promotion. Existing records that predate the policy are
reported honestly and are not silently rewritten.

Use `echo_veil_refresh_live` for continuously changing active state. If the
payload is byte-for-byte unchanged, Echo Veil retains the record ID and renews
only the encrypted expiry/provenance contract. If content changes, Echo Veil
creates a new protected Live version that explicitly supersedes the previous
record. A superseded or expired Live record cannot be refreshed, and the
always-available reader always rejects the operation.

When a pre-contract scoped-v2 profile first opens through the matching
embedding identity and authorization scope, Echo attaches an honest protected
Short-Term contract with `migration:pre-layer-contract` provenance to each
record in one transaction, then binds the required feature into the key
manifest. The source payload and lifecycle state are unchanged, and doctor
reports `migrated_memory_contracts`. Legacy-v1 profiles are not auto-upgraded.

Hosts using `AgentMemory` must not call `memory.oracle.sprout()` or mutate the
embedded Oracle directly. That low-level API cannot participate in the
adapter's cross-database contract transaction. `echo_veil_doctor` compares
lifecycle IDs, protected payload IDs, and protected contract counts; any
unpaired low-level vine makes the adapter unhealthy and cannot serve as a
Contextual Logic source.

Every recall result returns `memory_layer`, `provenance`,
`promotion_history`, confidence fields, and promotion/archive
recommendations. `layers_involved` summarizes the response and the optional
`layers` argument restricts candidates without changing their scores. Callers
must show those facts accurately, preserve ambiguous candidates, and return an
empty answer when no stored memory qualifies.

`echo_veil_context` is query-driven rather than an ID lookup. It recalls at
most two Contextual Logic roots through the ordinary confidence and
answerability gates, then follows only authenticated outgoing `related_ids`.
Traversal is capped at depth two, 20 evidence records, and 40 edges. A gated
root is never expanded. Every linked record is decrypted with its own protected
contract, checked for expiry and point-in-time validity, and labelled
`query_scored=false` with
`confidence_basis=protected_contextual_link`. The trace performs no synthesis;
the host must not portray linked evidence as an independent answer match.

The bundled full adapters explicitly select `qwen3-embedding:latest` through a
loopback-only Ollama client. Documents are embedded without a prefix; recall
queries use Qwen3's retrieval-instruction format. Each recall also creates a
subject-masked, predicate-focused query and requires its best protected passage
match to reach `0.42`. Both query vectors are generated in one bounded local
Ollama request. The default output dimension is 1,024 and the calibrated broad
recall minimum is `0.44`. The adapter never auto-pulls a model, follows
redirects, contacts a non-loopback origin, or falls back silently to hashing.

Recall responses expose `answerability_min_score`,
`answerability_rejected_count`, and a per-result `answerability_score` for
diagnosis. `echo_veil_doctor` reports `semantic-predicate-v1` when the gate is
active and `unavailable` for hashing or custom embedders that do not implement
it. The transform is syntax-based and contains no person names, domain-specific
terms, or lists of sensitive attributes.

### Always-available read-only recall

The executable adapter enables a conservative availability layer by default.
When the local Ollama service or configured model cannot run, it opens only an
existing owner-protected profile and queries the persisted keyed lexical index
at a minimum predicate score of `0.45` with at least two matched features.
Responses set `mode=always-available-read-only`, `degraded=true`,
`semantic_available=false`, and `lifecycle_mutated=false`. Per-result confidence
is capped in `fragmented_synthesis`; `availability_score` exposes the raw keyed
overlap separately. Callers must not describe it as semantic recall, coherent
assembly, or authoritative delivery.

The layer is SQLite read-only and cannot create a profile, remember, promote,
forget, reindex, lower its safe threshold, authorize inferential recall, or
mutate decay and reinforcement state. It still authenticates and decrypts the
shielded semantic contract for every returned record. A long-lived CLI, MCP,
or broker process makes a one-way transition into this mode if a later embedding
call detects a service outage.
Paraphrases may be missed. Corrupt storage, invalid keys, model-identity
mismatch, malformed embedding responses, and other trust failures still stop
the adapter rather than entering degraded mode. Disable the outage path with
`--no-availability-layer` or
`ECHO_VEIL_AVAILABILITY_LAYER=false`.

The same rules apply to degraded context tracing: the logic root must first
qualify through conservative keyed recall, every outgoing link must authenticate,
and the response remains explicitly degraded and non-semantic. No write or
lifecycle mutation is introduced by tracing.

```bash
ollama pull qwen3-embedding:latest
uv run --locked python scripts/quality_benchmark.py
```

Qwen3 supports instruction-aware retrieval and Matryoshka Representation
Learning dimensions; see the
[official model card](https://huggingface.co/Qwen/Qwen3-Embedding-8B) and
[Ollama embed API](https://docs.ollama.com/api/embed). Model quality, footprint,
and latency remain deployment tradeoffs, so qualify the real corpus before
making a profile primary.

The console entry point accepts payload-bearing requests only through stdin:

```bash
printf '%s' '{"action":"doctor","arguments":{}}' | echo-veil-agent rpc
echo-veil-agent mcp
```

### Serialized local broker

For Pi/Codex concurrency and warm preflight latency, `echo-veil-agent broker`
keeps one profile open and serializes bounded RPC/MCP calls over an owner-only
Unix socket. Its parent directory must be owned by the current user with no
group/other permissions; the socket is created as `0600`, peers are checked by
UID when supported, messages are capped at 1 MiB, and failures expose only a
generic error. Broker telemetry contains timing numbers and
`payload_included=false`, never the query, topic, payload, or filesystem path.

```bash
echo-veil-agent --state-dir /absolute/echo-state \
  --profile echo-universal-qwen3-v1 --scope local-user \
  --embedder ollama --embedding-model qwen3-embedding:latest \
  --embedding-dimension 1024 \
  --broker-socket /absolute/owner-only-run/echo.sock broker
```

Use `ECHO_VEIL_BROKER_SOCKET` for a native Pi extension, or pass
`--broker-socket /absolute/owner-only-run/echo.sock` to a shielded Pi/Codex
launcher. MCP startup validates semantic doctor readiness through the broker;
a missing/degraded broker stops before the host boundary. Do not use two
brokers for one profile. Direct non-broker writers remain protected by the
profile lease and generation/CAS checks, but the broker is the preferred
single-writer QoS path. Windows currently uses direct RPC because this broker
requires Unix-domain socket ownership semantics.

Codex consumes `mcp` over stdio. The checked-in `.mcp.json` uses the installed
`echo-veil-agent mcp` entry point when the repository is installed as a Codex
plugin. Install the matching Echo Veil distribution first. The plugin binds
the versioned `echo-universal-qwen3-v1` profile to the explicit `local-user`
scope instead of relying on a default that could drift. Its command hooks are
not trusted by installation: review the current `UserPromptSubmit` and
`PreToolUse(Agent)` definitions in `/hooks`; Codex binds trust to their exact
hashes and requires review again after a change.
Codex's experimental native memory must also be disabled for a
singular-authority session:

```toml
[features]
memories = false

[memories]
generate_memories = false
use_memories = false
```

The Echo hook still protects model startup if those settings drift, but a
healthy turn is not an exclusive-memory qualification while Codex native
memory is enabled.
For a direct local setup:

```bash
codex mcp add echo-veil -- \
  uv run --project /absolute/path/to/echo-veil --locked echo-veil-agent \
    --profile echo-universal-qwen3-v1 --scope local-user --caller codex \
    --embedder ollama \
    --embedding-model qwen3-embedding:latest --embedding-dimension 1024 mcp
```

Codex 0.146.0 direct collaboration delivered a delegated task without a fresh
task-specific Echo envelope; the child inherited the root turn's preflight.
The same direct environment also exposed a separate mutable second-brain plugin.
Direct root mode can therefore use protected Echo recall, but it is not a
singular-memory boundary, and direct child creation is unqualified. A direct
root preflight carries
`collaboration_authorized=false`; inheriting that root envelope never qualifies
a child, and agents must not reinterpret it as permission to delegate. Use the
artifact-bound shielded boundary when a fail-closed Codex turn is required:

```bash
printf '%s' 'Inspect the repository and report findings.' |
  echo-veil-shielded-run codex --cwd /absolute/path/to/repository
```

That launcher completes protected semantic preflight before creating Codex,
ignores ambient user configuration, and creates a temporary owner-only Codex
home containing only an owner-only copy of the existing auth file. When no
Codex auth file exists, an explicitly supplied `OPENAI_API_KEY` can provide
authentication. Ambient skills, model cache, goals, plugins, and session state
are not exposed. The launcher injects exactly one required Echo MCP server,
enables strict config parsing, disables native memory, Chronicle, goals,
plugins, the remote plugin catalog, account-level apps/MCP connectors, and the
current `multi_agent` collaboration feature, and uses an ephemeral session. It defaults to
`--sandbox read-only`; workspace mutation and non-Git
working directories require the explicit `--sandbox workspace-write` and
`--allow-non-git` opt-ins. It does not claim protected subagents because it
prevents their creation.

Codex `0.146.0` is checked before launch. First run the same command with
`--print-codex-artifact-receipt`, review the path-free receipt out of band, and
pin its `artifact_authority_id` through
`ECHO_VEIL_CODEX_ARTIFACT_AUTHORITY_ID` or
`--codex-artifact-authority-id`. The receipt hashes the Codex executable, exact
installed Echo wheel and entry points, plugin/hook/MCP bytes, model,
configuration, state authority, and optional broker endpoint/signing authority.
One-byte drift blocks startup. `--codex-interactive` creates an isolated
interactive profile under the same receipt. It installs the verified Echo hook
and skill payloads directly, keeps Codex's plugin loader disabled so account
plugins cannot merge into the profile, and enables one required Echo MCP
server. The repository implementation is
release-pending; an ambient mutable checkout or matching version alone is not
current authority evidence.

OpenClaw loads `integrations/openclaw` as an exclusive native memory capability
with the same nine tools. Pi loads a
native TypeScript extension package. Algo CLI uses the same protected
`AgentMemory` contract through its in-process bridge. Shielded Codex uses a
receipt-bound stdio MCP server plus verified root hook/skill assets; Claude
Code uses its plugin-bundled stdio MCP server. Hermes, OpenCode, Droid, and Goose use their
documented stdio MCP configuration surfaces. Every full adapter exposes:

- `echo_veil_remember` — opt-in Live, Short-Term, or Contextual Logic capture;
- `echo_veil_refresh_live` — renew unchanged Live state or create an explicit
  protected superseding Live version when content changes;
- `echo_veil_promote` — evidence-bearing Live → Short-Term or Short-Term →
  Long-Term promotion;
- `echo_veil_recall` — lifecycle-mutating, confidence-gated retrieval with an
  optional semantic-layer scope;
- `echo_veil_context` — bounded trace from confidence-checked Contextual Logic
  roots to authenticated outgoing evidence;
- `echo_veil_list` — bounded administrative inventory with no semantic
  retrieval, lifecycle mutation, reinforcement, or decay;
- `echo_veil_forget` — payload-first local erasure;
- `echo_veil_doctor` — adapter and core readiness reporting; and
- `echo_veil_reindex` — explicitly confirmed protected retrieval-index rebuilds.

The RPC boundary also supports `echo_veil_rotate_key` for confirmed, bounded,
resumable re-encryption and `echo_veil_retire_key` for separately confirmed
old-key retirement after backup accounting. Ordinary MCP servers expose only
the nine memory tools above. A reviewed operator-only MCP process may add
`--operator-tools` (or `ECHO_VEIL_OPERATOR_TOOLS=true`) to expose both
maintenance schemas. The server rejects direct calls to hidden tools even when
a client already knows their names. Native hosts must not implement rotation
themselves.

Codex, Claude Code, Hermes, Pi, OpenCode, and Droid ship the same
`echo-veil-memory` Agent Skill. Goose embeds the equivalent policy in its recipe.
OpenClaw injects that ritual through its selected `memory` capability, and Algo
CLI injects it directly into ordinary-chat and Agent Block prompts. The ritual
requires doctor-backed readiness, minimal recall for every substantive task,
Contextual Logic tracing for causal or decision questions, metadata-preserving
ambiguity/conflict handling, disciplined layer transitions, and fail-closed
behavior without plaintext fallback. Static packaging proves policy
availability, not that a host invoked it; qualify the actual installed runtime.

A host-delivered exact-turn preflight can satisfy the initial ritual without
making the model repeat tool calls. Its compact `runtime_status` must use
`echo-veil-runtime-status-v1` and report semantic readiness, completed doctor
and recall checks, completed Contextual Logic when required,
`ritual_satisfied=true`, and `lifecycle_mutated=false`. The status and evidence
are bound to that exact receipt/hook turn. They do not authorize a write,
inferential access, collaboration, or reuse on another turn. Missing or
inconsistent status falls back to the explicit tool ritual; degraded status
never satisfies it.

Goose's recipe prompt explicitly calls doctor and a two-slot minimal recall
before waiting for a separate mutation request. Do not launch the recipe with
`--no-profile`: Goose 1.41.0 suppresses recipe-defined extensions under that
flag. The recipe detects an absent Echo tool catalog and stops rather than
continuing with host memory, but the normal recipe is policy-driven rather than
a hard model gate.

For required headless use, `echo-veil-shielded-run goose` performs doctor and
semantic recall before a Goose process exists. It then starts Goose with
`--no-profile`, `--no-session`, and one explicit Echo MCP extension. The
apparent `--no-profile` difference is intentional: the launcher supplies Echo
directly through `--with-extension`, while the portable recipe relies on its
recipe-defined extension. Only the reviewed `developer` builtin may be added.

Pi `0.84.1` enforces one signed `preflight_v2` transaction in code. Its input
hook requests lifecycle-neutral doctor/recall/applicable Contextual Logic
evidence; expanded skill/template prompts receive a replacement receipt. The
receipt binds the query, session, turn, model, active tool manifest, Pi artifact
authority, evidence, embedding identity, nonce, and short expiry. Pi consumes
it once at `before_provider_request` and verifies that the exact protected
context remains in the outbound payload. Mid-run steering/follow-up is blocked
because it can bypass a fresh agent-start boundary. Missing, degraded, altered,
expired, replayed, cross-turn, cross-model, cross-tool, or stripped evidence
blocks before a provider or tool call, without a host-memory fallback.

Evidence is capped at 16,000 characters and an estimated 2,400 tokens. Payloads
are omitted whole—context evidence first, then logic roots, then recall
payloads—while authenticated record shells and every required
ambiguous/conflicting candidate remain. Preflight telemetry is payload-free and
reports only bounded doctor/recall/context/total latency, result count, and
whether Contextual Logic ran. Every Echo tool is sequential; mutation,
reindexing, and inferential access require a fresh one-use UI confirmation.
`/echo-veil-availability` is the only degraded path and is manual, read-only,
non-authoritative, and incapable of authorizing an agent or mutation.

The Pi package is compiled against the real pinned `0.84.1` types and bound to
`integrations/pi/artifact-receipt.json`; both the extension and shielded launcher
require its out-of-band authority ID. The isolated `echo-veil-shielded-run pi`
mode disables sessions, ambient extensions/skills/templates/context files, and
built-in tools, then loads only the receipt-bound Echo package. Direct ambient
Pi stacks remain weaker because a later extension can alter a provider payload
after Echo's hook. Until this implementation is committed and released, the
currently installed Pi version remains release-stale authority evidence.

OpenClaw uses three runtime hooks around its selected memory capability.
`before_agent_reply` claims the turn and can return a synthetic failure before
model startup, `before_prompt_build` injects protected context plus a random
short-lived attestation, and `before_agent_run` consumes that attestation once
before allowing model execution. Both
`plugins.entries.echo-veil.hooks.allowConversationAccess` and
`allowPromptInjection` must be true, `plugins.slots.memory` must equal
`echo-veil`, and the built-in transcript-writing
`hooks.internal.entries.session-memory.enabled` setting must explicitly equal
`false`. The plugin checks all four conditions and blocks before model startup
when any condition drifts. Every model used for a singular-authority session
must also set `agentRuntime.id="openclaw"`. OpenClaw's native Codex app-server
fast path does not currently run the early reply and pre-model hook pair, so it
is explicitly outside the hard-gate claim even though prompt construction
still runs.

Codex and Claude Code use `echo-veil-preflight-hook` from their bundled
`UserPromptSubmit` and `PreToolUse(Agent)` lifecycle configuration. Each
invocation reads only a bounded hook JSON object, ignores transcript and
working-directory paths, validates the exact scoped-v2 Qwen3 profile, performs
two-slot, non-inferential recall, and adds a depth/record-bounded Contextual
Logic trace for causal prompts detected across English, Spanish, French,
German, Portuguese, Italian, Chinese, Japanese, and Korean. Returned records retain layer, score,
confidence, provenance, temporal state, and promotion/archive guidance. The
hook serializes them as escaped untrusted JSON. Evidence obeys both a character
cap and a conservative UTF-8 token estimate. A record larger than the
per-record or total preflight budget is omitted with its authenticated shell,
ID, byte-independent character count, and omission reason; it is never silently
truncated into a different statement. Ambiguous/conflicting shells are never
dropped to make the budget pass.

Codex's matcher explicitly covers `Agent`, `SpawnAgent`, `spawn_agent`, and
`collaboration.spawn_agent`. The parser accepts only those bounded aliases and
still requires exactly one supported task field. This avoids assuming that the
host always normalizes its current collaboration namespace to the legacy
`Agent` alias. It does not turn a host path that omits `PreToolUse` into an
enforcement boundary; the installed collaboration router was observed doing
exactly that and remains unqualified.

On any invalid input, unavailable semantic embedding, degraded transition,
integrity/readiness failure, ambiguity/competing-pair loss, or output overflow,
the hook returns one generic structured stop for a root prompt or a deny
decision for an Agent tool. It never emits the local error, path, transcript,
or a plaintext fallback. A permitted Agent call receives a complete copy of
its original arguments with only its task field rewritten to prepend the
task-specific protected context. The separate always-available layer remains
useful for explicitly labelled keyed read-only inspection, but it does not
satisfy a required semantic model-turn preflight.

`ECHO_VEIL_FORCE_AGENT_PREFLIGHT_FAILURE=1` is a deny-only installed
qualification control for Codex and Claude Code. It leaves the root prompt
preflight unchanged and forces only the supported `PreToolUse(Agent)` boundary
to deny before opening Echo. `ECHO_VEIL_FORCE_TASK_PREFLIGHT_FAILURE=1` provides
the equivalent child-only probe for OpenCode's `Task` hook. Neither control can
authorize a turn, select another memory source, alter protected context, or
redirect a subprocess. Use each only for an isolated healthy-root/denied-child
smoke and unset it afterward.

Claude Code auto-memory is a separate plaintext mutable authority and is on by
default. Disable it globally before claiming singular authority while keeping
normal plugin hooks enabled:

```json
{
  "autoMemoryEnabled": false,
  "env": {
    "CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"
  }
}
```

Put that configuration in `~/.claude/settings.json`. Do not use `--bare` or
`--safe-mode` as a shortcut because both modes disable the Echo hook boundary.
The Claude preflight requires `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` and fails
closed before opening Echo when it is absent.

Droid invokes that same Python boundary through a fixed POSIX wrapper. Its
packaged `UserPromptSubmit` and `PreToolUse(Task)` definitions request root and
task-specific protected recall. The wrapper accepts only an absolute,
executable `ECHO_VEIL_PREFLIGHT_COMMAND` and exits with Droid's blocking status
when it is missing or fails. The hook intentionally has no Droid-level timeout:
the host treats a timeout as a non-blocking hook error. Installations with
`allowManagedHooksOnly=true` are unqualified unless these exact hooks are
provisioned and re-tested as managed hooks.

The installed Droid 0.180.0 `exec` path did not invoke either plugin or user
prompt hooks, so bare `droid exec` is explicitly outside the hard-gate claim.
`echo-veil-shielded-run droid` provides the qualified headless boundary:
protected preflight completes before host creation, prompt/context travel only
through child stdin, built-in skills are disabled, and `Task` is disabled
because `exec` cannot prove a child-specific preflight. Interactive hook
behavior remains a separate installed-host qualification.

OpenCode loads `integrations/opencode/.opencode/plugins/echo-veil-shield.js`
from either a project or global plugin directory. Its `chat.message` hook runs
the same RPC-only semantic preflight and prepends the bounded evidence to the
current user text. A `chat.params` hook requires that exact message ID to have
completed preflight before provider parameters are assembled. Supported
`Task` tool calls receive a task-specific preflight with only their `prompt`
rewritten; every other argument is preserved. Automatic continuation after
compaction is disabled because the synthetic turn has no new user intent to
bind. The child uses a fixed argument vector, an explicit environment
allowlist, no shell, bounded output, and a generic failure. OpenCode `--pure`
disables external plugins and is not a singular-authority mode.

Hermes loads `integrations/hermes/plugin` as an opt-in general plugin. Its
`pre_llm_call` hook runs the RPC-only semantic preflight and contributes a
bounded ephemeral context block below Hermes's default spill threshold. Its
`llm_execution` middleware then requires the exact session/task/turn
attestation and its random per-turn request nonce before calling the provider.
Hook failure is intentionally
swallowed by Hermes, so the middleware—not the observer hook—is the hard
boundary. In singular mutable-memory mode, set both
`memory.memory_enabled=false` and `memory.user_profile_enabled=false`.
For a host-startup boundary, use
`echo-veil-shielded-run hermes --model MODEL`. It preflights before host
creation, copies only the digest-bound plugin into an isolated owner-only
`HERMES_HOME`, generates a native-memory-off and Echo-only configuration, and
binds stdin to a one-turn nonce. The plugin registers `hermes echo-veil-run`
last, after the required hook and middleware. Plugin import or registration
failure therefore leaves no requested command and cannot fall through to a
model call. This path intentionally supports one local loopback provider and
the Echo MCP toolset only.

Do not collapse these integrations into one enforcement claim:

- **Hard pre-model gate:** Algo CLI required mode, OpenClaw models pinned to the
  OpenClaw runtime, receipt-bound Pi, and a loaded Hermes shield plugin own runtime
  boundaries that stop the model turn when protected preflight is absent or
  fails. OpenClaw's claim additionally depends on the exclusive Echo slot,
  both hook permissions, native session-memory being explicitly disabled, and
  does not cover its Codex app-server runtime. Hermes general plugins are
  opt-in and registration failures do not abort host startup, so every
  installed run must verify that `echo-veil-shield` loaded.
- **Hard shielded gate:** `echo-veil-shielded-run` starts Codex, Pi, Droid,
  Goose, or Hermes only after a complete protected semantic preflight. Codex
  starts with one required Echo MCP server, isolated auth, and no ambient
  config/skills/cache; native memory, Chronicle, goals, plugins, and
  parallel-agent paths are disabled; its isolated interactive profile uses the
  same artifact binding. Pi loads only its receipt-bound extension in a clean
  one-turn home. The
  Droid path disables `Task`; the Goose path loads no default profile or
  session and adds only the explicit Echo extension plus an optional reviewed
  `developer` builtin. The Hermes path uses a digest-bound plugin, isolated
  temporary home, disabled native memory, launch nonce, fixed loopback
  provider, and Echo-only toolset. Ordinary Hermes plugin mode remains
  conditional on visible plugin load. This claim does not extend to direct Codex
  collaboration, bare `droid exec`, interactive Droid, or ordinary Goose
  recipe runs.
- **Hard root/tool gate:** Claude Code stops root user prompts through native
  `UserPromptSubmit` hooks and denies supported `Agent` tool
  spawns unless task-specific protected recall succeeds. OpenCode gates root
  prompts and supported `Task` spawns through the same contract.
  Direct Codex root turns can receive protected Echo context, but the observed
  direct environment exposed competing mutable memory and collaboration did not
  receive child-specific preflight; neither is a singular-authority claim.
  Claude Code must not run with `--safe-mode` or `--bare`, which disable plugin hooks.
  OpenCode must not run with `--pure`. Droid's packaged native hooks require a
  separate interactive qualification and are not covered by the headless
  launcher claim. Direct
  `SubagentStart` is context-only in current host APIs and cannot fail closed,
  so out-of-band spawn paths remain unqualified. The spawn paths require
  installed-host smokes before release and must not yet be described as full
  Pi/Algo-equivalent enforcement.
- **Artifact-bound provider gate:** AIP selects Echo as its required backend
  without a shadow store and wraps every provider created by its runtime builder
  before Agent, SDK, workflow, chat, streaming, or vision generation. Required
  semantic preflight failure produces no underlying provider call. Qualification
  additionally requires AIP's exact PEP 610 wheel-hash and `RECORD` receipt;
  manually constructed raw providers are outside the claim.
- **Policy-driven recipe:** Normal Goose recipe runs use equivalent
  instructions. Recipe and MCP loading prove that the protected tools and
  policy are available, not that each turn invoked them or stopped on failure.
- **Readiness-only:** Mercury cannot be a singular authority while its native
  mutable memory stores remain active.

A host-level “fail-closed” claim requires evidence from its real pre-model stop
boundary. Shared contract tests and successful MCP discovery are necessary
adapter evidence, but they are not substitutes for that host evidence.

Use `python scripts/verify_host_authority.py --installed` to compare the
current checkout and installed host versions with the exact evidence snapshot.
The report keeps qualified boundaries, conditional gates, externally unbound
evidence, repository-only adapters, release-pending/stale runtimes, and blocked hosts distinct. Hosts with an
artifact receipt also fail current status on a missing, editable, mismatched,
or tampered installation. It is a drift detector, not a replacement for
installed model/provider outage smokes.

Hook-provided memory becomes part of the authorized host/model context and may
be retained in that host's transcript. Echo's shield protects the source
record, vector, metadata, and lifecycle at rest; it cannot encrypt a model's
already-authorized plaintext context. Keep the preflight minimal, use host
session-retention controls where appropriate, and never claim the host
transcript is inside Echo's shield.

Selecting Echo Veil for a required-protection host makes it the primary
mutable agent-memory store. Existing host memory files, wiki pages, and
curated documents remain valid evidence when Echo has no answer; they are
not deleted or silently written. OpenClaw installation still selects
`plugins.slots.memory=echo-veil`. Skill-capable hosts share the same ritual,
Goose receives it through the recipe or shielded launcher, Algo required
mode enforces it in runtime code, and Grok Build injects protected context
without claiming a singular pre-model stop.

The shield boundary covers dynamic records sent through Echo Veil, including
their semantic layer, provenance, promotion history, Contextual Logic links,
retrieval vectors, and lifecycle state. It does not encrypt a host's source
files, skills, configuration, conversation transcript, model context, or
pre-existing memory database merely because the host loads this adapter.
Every harness must treat those static assets as source material, not as a
second protected memory authority. If a harness requires
protected continuity, it must write a bounded Live or Short-Term seed crystal
through Echo, deliberately promote it when warranted, and use Echo recall or
context operations. A required-protection host must bypass its legacy memory
catalog rather than silently falling back to it.

`ECHO_VEIL_STATE_DIR`, `ECHO_VEIL_PROFILE`, and `ECHO_VEIL_SCOPE` select the
storage and authorization boundary. `ECHO_VEIL_CALLER` binds a stable
`caller:<host>` transport marker into remember, refresh, and promotion
provenance. Bundled adapters set it explicitly. Caller identity is attribution,
not durable evidence: a caller-only record cannot be promoted to Long-Term or
used to create Contextual Logic without separate non-caller provenance. The embedding
backend is selected with `ECHO_VEIL_EMBEDDER`; Ollama model, dimension, URL, and
timeout use the corresponding `ECHO_VEIL_EMBEDDING_*` and
`ECHO_VEIL_OLLAMA_URL` variables. `ECHO_VEIL_AVAILABILITY_LAYER` controls the
read-only outage path. `ECHO_VEIL_PROFILE_LOCK_TIMEOUT` controls how long a
writable process waits for the profile-wide lease. Bundled adapters use a
versioned shared Qwen3 profile, `echo-universal-qwen3-v1`, for harnesses in the
same local-user authorization domain. Use a separate profile when a host acts
for a different user, trust boundary, or embedding identity. One
`AgentMemory` instance owns the writable profile lease at a time; a second
instance waits and then fails closed rather than loading and later persisting a
stale process-local L1 snapshot. Long-lived MCP transports validate the profile
at startup and release it, then open and close one instance per tool call. Algo
CLI opens and closes one instance per memory operation. A direct SDK caller
must close its instance explicitly.

The adapter payload and lifecycle databases cannot share one SQLite
transaction. Startup therefore checks their ID sets before serving requests.
Lifecycle state without an encrypted payload is treated as an interrupted
remember and removed through `Oracle.forget()`. An encrypted payload without
lifecycle state is preserved and blocks startup because automatic deletion
would be ambiguous. Restore or audit that record explicitly; do not weaken the
check.

Embedding identity is immutable for a non-empty profile. Bundled profile names
therefore remain stable across compatible releases; silently changing a
default would strand protected memory. Run `echo_veil_doctor` against the
existing profile before choosing a migration target. To move a compatible
legacy or scoped profile to Qwen3, use the explicit in-process migration below.
It decrypts one source record at a time, re-embeds it into an empty target
profile, preserves explicit supersession links and protected semantic
contracts, and creates no plaintext export file. It does not modify the source
profile. It creates new vine IDs and fresh lifecycle state; scores,
reinforcement age, locks, and archive position are not copied.

```bash
uv run --locked python scripts/migrate_agent_profile.py \
  --source-profile old-hashing --target-profile new-qwen3 \
  --source-embedder hashing --confirm
```

For an existing semantic source, select `--source-embedder ollama` and provide
its exact model and dimension. Both profiles remain encrypted at rest; plaintext
exists only transiently inside the authorized migration process. Do not copy
or mix old vectors. If the resolved `latest` tag digest changes, review the
model change and migrate to a new profile instead of weakening the mismatch
check. Long-lived processes recheck the resolved digest and maximum dimension
before every embedding batch.

Verify the resulting pair through the read-only migration verifier:

```bash
uv run --locked python scripts/verify_agent_profile_migration.py \
  --source-profile old-hashing --target-profile new-qwen3
```

The verifier derives process-local HMAC tokens from one decrypted record at a
time and emits no payloads or per-record fingerprints. It requires exact
content, effective-time, supersession-edge, retrieval-index, and protected
contract equivalence. A legacy source must appear as reviewable Short-Term with
`migration:profile-transfer` provenance. A scoped source must preserve its
complete four-layer contract. `--allow-target-extras` permits later target
writes but never permits a missing or altered source record.

Legacy host catalogs require a separate content-review workflow. Echo never
silently absorbs a harness memory file. `scripts/migrate_host_memory.py`
accepts one owner-only JSON list containing at most 200 strings and defaults to
a payload-silent dry run:

```bash
uv run --locked python scripts/migrate_host_memory.py \
  --source /path/to/host-memory.json \
  --profile echo-universal-qwen3-v1 --scope local-user --caller host-name
```

The report exposes counts, record indices, reason categories, and hashes but no
payloads or filesystem paths. Raw transcripts, invalid text, and oversized
Short-Term records are ineligible. Developer paths, credential-like content,
and dense seed crystals require manual review. A protected import requires the
exact `--confirm IMPORT_REVIEWED_HOST_MEMORY` phrase; review-required records
also require an explicit `--allow-review-required`.

Successful imports enter Short-Term with caller and migration provenance. The
utility verifies an exact protected inventory in a reopened profile and in a
separate read-only process, writes an owner-only hash receipt, and retains the
source by default. Plaintext retirement requires both `--retire-source` and
`--retire-confirm RETIRE_VERIFIED_PLAINTEXT_SOURCE`. It happens only after
verification and is a logical unlink, not physical secure erasure. A failed or
partial import retains the source; records created before an import failure are
rolled back while the exclusive profile lease is still held.

The bundled adapter's retrieval path uses encrypted passage vectors with
MaxSim, keyed-hash lexical features, topic-aware MMR diversity, and explicit
`effective_at`/`supersedes` metadata. `recall(as_of=...)` can select the fact
valid at a historical point without discarding later corrections. Responses
also report `ranking_margin` and `ranking_ambiguous`; callers should retain both
leading records when the margin is at most `0.05` instead of pretending an
adjacent policy or responsibility record is a certain winner. Run
`echo_veil_reindex` after upgrading an existing profile so its derived protected
retrieval data matches the current schema.

Recall separately reports `competing_memory_detected` and bounded
`competing_memory_groups` when two or more returned current records share one
authenticated protected topic. This is a conservative `possible_conflict`
signal, not a semantic contradiction judgment: compatibility and resolution
remain `not_evaluated`. Preserve every returned member with its own layer,
provenance, confidence, and temporal fields. Resolve only through explicit
supersession or a protected Contextual Logic `contradiction_resolution` linked
to the evidence. Direct SDK recall may report `effective_top_k=2` after a
`top_k=1` request solely to prevent the strongest authenticated pair from being
hidden.

The RPC/MCP boundary defensively uses at least two recall slots even if a legacy
caller requests `top_k=1`; the response reports `requested_top_k`,
`effective_top_k`, and `ambiguity_candidates_preserved`. Native OpenClaw and Pi
schemas require a minimum of two. OpenClaw also reports the measured
fresh-process boundary as `host_transport.elapsed_ms`; do not compare that host
and process startup number directly with in-process retrieval latency.

Mercury is intentionally readiness-only. Its current public
[Skills contract](https://mercuryagent.sh/docs/reference/skills) can elevate
the built-in
[`run_command`](https://mercuryagent.sh/docs/reference/built-in-tools) tool but
does not document arbitrary MCP or structured custom-tool registration.
Sending protected content through shell arguments, pipelines, temporary files,
URLs, or environment variables would create plaintext traces, so the included
Mercury skill refuses remember, recall, and forget until the host exposes a
reviewed structured boundary. Its
[Second Brain documentation](https://mercuryagent.sh/docs/reference/second-brain)
also states that disabling Second Brain falls back to basic Long-Term fact
search. Current source constructs separate Short-Term, Long-Term, and Episodic
stores regardless, so there is no supported all-memory-off switch. Mercury is
therefore incompatible with singular-authority mode until a reviewed upstream
backend or hook routes the full lifecycle through Echo, suppresses every native
mutable store, and aborts on preflight failure. See
[`integrations/README.md`](../integrations/README.md) for install and validation
commands for every host.

## Integration flow

For each memory worth retaining:

1. Store the authorized application payload in the host's protected content
   store.
2. Create a stable embedding using one model/version and dimension.
3. Call `Oracle.sprout(topic, embedding)` and associate the returned `vine_id`
   with the payload.

For each user turn:

1. Authorize the user before loading or embedding private content.
2. Embed the current intent with the same embedding model and dimension.
3. Call `Oracle.observe(intent)` exactly once for the turn. This advances drift,
   proximity, twilight, eviction, and persistence state. A returning relevant
   intent also rescores and automatically reinforces a twilight vine before it
   expires.
4. Rank eligible active vines by their newly computed score. Search cold L2
   metadata with `Oracle.search_index(intent)` when the active set is
   insufficient, then resolve returned vine IDs through the authorized payload
   store.
5. Call `Oracle.check_generation_gate(score)` before giving retrieved content to
   a model. Surface `GenerationGated` to the user; never silently invent an
   answer.

Echo Veil intentionally does not call the language model. The host decides how
retrieved payloads are assembled into model context after authorization and
confidence gating.

## Minimal development adapter

```python
import numpy as np

from echo_veil import GenerationGated, Oracle

oracle = Oracle(environment="development")  # plaintext; local testing only
payloads: dict[str, str] = {}

anchor = np.array([1.0, 0.0, 0.0])  # replace with your embedding model
vine = oracle.sprout("estimate labor rate", anchor)
payloads[vine.vine_id] = "Synthetic example labor rate is $137/hour."

intent = np.array([1.0, 0.0, 0.0])
oracle.observe(intent)
candidates = sorted(oracle.workspace.active(), key=lambda item: item.score, reverse=True)

if candidates:
    candidate = candidates[0]
    try:
        policy = oracle.check_generation_gate(candidate.score)
    except GenerationGated as gated:
        # Ask for clarification or explicit override as directed by gated.policy.
        print(gated.policy.indicator)
    else:
        authorized_payload = payloads[candidate.vine_id]
        print(policy.indicator, authorized_payload)
```

The example reads the exported `Workspace` collaborator to rank active vines
after `observe()`. Do not mutate returned `Vine` instances. Lifecycle mutations
must go through `Oracle.reinforce()`, `lock()`, `unlock()`, `set_crests()`, and
`forget()`.

## Security modes

| Mode | Required shield | Intended use |
|---|---|---|
| `development` / `test` | `NullCryptoShield` by default | Local tests only; no confidentiality |
| `staging` | `AesGcmCryptoShield` or reviewed staging-ready shield | Encrypted stored anchors; AES-GCM decrypts transiently for scoring |
| `local-private` | `LocalOpenFheCryptoShield` | Local native CKKS without enclave attestation |
| `production` | `EnclaveCryptoShield` | Attested CKKS, hardware isolation, and proof-gated access |

Production construction is fail-closed. Use
`build_production_enclave_shield_from_env()` only after following
[`DEPLOYMENT_RUNBOOK.md`](DEPLOYMENT_RUNBOOK.md). Cloudflare is a gateway, not
the enclave; the client must still verify fresh downstream evidence and an
approved measurement.

For staging, keep the AES key in a secret manager and reuse the same key when
reopening persisted protected vectors:

```python
from pathlib import Path

from echo_veil import AesGcmCryptoShield, Oracle, SQLiteStore

shield = AesGcmCryptoShield.from_env()
store = SQLiteStore(Path.home() / ".echo-veil-store" / "echo-veil.db")
oracle = Oracle(environment="staging", shield=shield, storage=store)
```

Always close the store on shutdown, or use it as a context manager. Protect and
back up the database and cryptographic state together. On Windows, use a
dedicated database directory: `SQLiteStore` creates a missing parent with a
private DACL, but rejects an existing parent that is not already private rather
than rewriting permissions on a shared or working directory.

## Confidence behavior

- Solid and Coherent results may proceed under normal host policy.
- Fragmented results must expose gaps and inferential assembly.
- Inferential results raise `GenerationGated` until the user explicitly
  authorizes an override.
- Data Obscurity always raises `GenerationGated`; an override cannot bypass it.

An application should record the selected vine IDs, confidence policy, user
override event, and model-input provenance without logging private payloads,
secrets, raw protected vectors, proofs, or attestation credentials.

## Operational checks

- Call `oracle.capability_report().as_dict()` at startup and surface blockers in
  readiness/health reporting.
- For `AgentMemory`, use `doctor()` and retain each readiness fact separately.
  Do not collapse installation, supported version, enablement, crypto, write,
  index, retrieval, persistence, restart, rotation, and health into one flag.
  Do not log the profile path, raw scope, queries, payloads, vectors, keys, or
  exception representations that may contain them.
- Rotate a scoped-v2 profile with repeated confirmed `rotate_key()` calls until
  it reports `verified`. Retire the previous key only after record-reference
  verification and an explicit backup-accounting confirmation. Legacy-v1
  profiles must migrate to a fresh scoped-v2 profile first.
- Keep one embedding model/version and dimension per Oracle/store. Migrate to a
  new profile when changing dimensions or model identity; use only the reviewed
  hashing-to-Qwen migration above for legacy adapter profiles.
- Treat every query as tenant-scoped. Do not share an Oracle or payload lookup
  across authorization boundaries without explicit tenant isolation.
- Call `oracle.forget(vine_id)` to remove the matching Echo Veil-managed
  L1/L2/L3 state. `SQLiteStore` performs that deletion atomically and leaves a
  live vine retryable when the transaction fails.
- Treat `forget()` as one step in the host's erasure workflow, not a complete
  erasure claim. Delete the authorized payload, tenant mapping, separately
  managed conflict/fossil artifacts, and applicable backups under host policy.
  SQLite `secure_delete` reduces ordinary page remnants, but Python memory,
  WAL files, backups, and storage media do not provide guaranteed physical
  erasure through this API.
- For user-requested erasure, revoke payload access first, enqueue an auditable
  deletion job, idempotently retry both `forget()` and host-store deletion, and
  verify every in-scope system before marking the request complete.
- Benchmark SQLite/LSH latency and recall on the real corpus. Its local durable
  behavior is not a distributed or exabyte-scale storage guarantee.
