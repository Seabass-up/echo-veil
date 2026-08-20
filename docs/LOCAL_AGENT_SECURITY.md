# Local agent-memory security contract

This document defines the security boundary of
`echo_veil.agent_memory.AgentMemory`. The adapter defaults to a local staging
security subsystem and may qualify for the separately defined host-trusted
local-production class only when every `capabilities_v1` gate passes. It is not
the attested production enclave described in
[`DEPLOYMENT_THREAT_MODEL.md`](DEPLOYMENT_THREAT_MODEL.md), and an importable
package or enabled feature flag is not evidence that an application uses it.

## Local-production readiness

`capabilities_v1` is an RPC-only diagnostic contract. It does not alter or
satisfy preflight. A positive local-production result requires all of the
following at once: scoped authenticated encryption, complete protected
semantic state, digest-bound Qwen3 embeddings, verified profile ownership and
permissions, an immutable installed artifact, authenticated backup plus an
actual restore drill, a qualified host enforcement boundary, reviewed key
custody, an empty reconciliation backlog and quarantine, zero plaintext
fallback attempts, a completed key migration, an available model, and an
explicit `local-production` selection.

Current scoped profiles use `file-v1` key custody and therefore remain
`local-staging`. `ECHO_VEIL_DEPLOYMENT_MODE=local-production` is fail-closed:
it preserves that requested mode in diagnostics but blocks all non-diagnostic
RPC actions until independent evidence qualifies every gate. It never silently
downgrades to staging or Offline Read-Only Recall. A failed Qwen3 startup or a
degraded/open embedding circuit produces `EV-MODEL-UNAVAILABLE` and blocks the
requested local-production operation. Stable remediation codes map each failed
gate to payload-free operator guidance.

Even after local qualification, the report remains explicit:
`hardware_isolated=false`, `remotely_attested=false`, and
`host_compromise_protected=false`. Only the separately verified enclave class
may set `production_ready=true`; the two readiness booleans are mutually
exclusive. Every language adapter rejects reports that combine the classes,
attach enclave claims to local readiness, or advertise a ready tier while both
readiness booleans are false.

Installed-artifact evidence is operator-confirmed and path-free. The verifier
requires a retained local wheel with a matching PEP 610 SHA-256 receipt,
compares the installed Echo package bytes with that wheel, verifies the three
declared console entry points, and binds their current bodies into one content
authority ID. `echo-veil-agent qualify artifact --confirm` records that result
inside the profile-bound encrypted readiness store. Doctor rehashes the active
installation instead of trusting the stored boolean, so an editable checkout,
missing wheel, changed package, or entry-point drift makes both artifact and
dependent host evidence false.

Host-boundary evidence is accepted only from a fixed in-process verifier; there
is no generic agent RPC, environment switch, or unsigned capability input for
it. Qualification requires a healthy signed preflight-v2 run, a forced-outage
run that blocks before any provider, model, agent, or tool activity, and no
competing mutable memory. Its short-lived receipt binds the exact host artifact,
Echo artifact, preflight authority, profile hash, scope ID, and boundary kind.
Runtime evaluation additionally requires the receipt's `host_id` to equal the
actual invoking caller. A Codex receipt on a shared profile therefore cannot
qualify Pi, OpenClaw, or any other harness; dependent backup and restore
readiness also remain false for the mismatched caller.
The receipt remains diagnostic evidence only and never satisfies or modifies a
turn receipt. Direct Codex collaboration and other documented soft boundaries
remain excluded.

New backups bind the current artifact and host authority IDs when those gates
are active. Recording a different artifact, allowing host evidence to expire,
or detecting installed-byte drift prevents the older backup from satisfying
local readiness; the authenticated archive remains available for an explicit
recovery operation. A fresh backup and restore drill are required after the new
authority is qualified.

## Protected path

For a scoped-v2 profile, one ordinary remember operation follows this sequence:

1. Validate and bound the topic, payload, identifiers, timestamps, and vectors.
2. Bind the profile to one normalized authorization scope.
3. Serialize the topic and payload into a versioned record envelope.
4. Validate a semantic-layer contract containing provenance, retention state,
   promotion history, and any typed Contextual Logic relationships.
5. Encrypt the envelope, semantic contract, and each retrieval vector
   independently with
   AES-256-GCM and a fresh 96-bit nonce.
6. Authenticate the object type, opaque scope ID, record ID, schema version,
   key ID, and vector ordinal/dimension as associated data.
7. Commit the encrypted payload, protected semantic contract, protected vectors,
   and keyed lexical features as one `pending` SQLite transaction.
8. Persist the Echo Veil lifecycle anchor under the same stable record ID.
9. Mark the payload record `committed`.

Startup reconciles the only two safe interrupted states. A pending payload with
matching lifecycle state is committed; a pending payload without lifecycle
state is removed. Lifecycle state without a payload is forgotten. An
unexplained committed payload orphan is preserved and blocks startup for
operator review. Recall considers only committed, non-quarantined records,
decrypts after candidate selection, and checks the profile scope binding before
opening either database.

Layer-scoped recall authenticates each candidate contract before applying the
requested semantic-layer filter; the filter never alters a score.
`echo_veil_context` then reuses ordinary confidence-checked recall for at most
two Contextual Logic roots. It follows only record-bound encrypted outgoing
links and separately authenticates every linked contract and payload. Gated,
expired, corrupt, missing, or point-in-time-invalid evidence is omitted and
reported as an incomplete trace. Hard depth, record, and edge limits prevent a
protected relationship graph from becoming an unbounded response.

Competing-memory detection uses the deterministic keyed topic token only after
the selected record's encrypted envelope authenticates and the token is
recomputed with that record's key and scope. A copied or swapped token
is rejected instead of manufacturing a conflict group; writable mode also
persists a quarantine marker. Returned same-topic current pairs are labelled
only as `possible_conflict`; no content compatibility or resolution is
inferred. Groups and member-ID lists are hard-bounded, and plaintext topics are
not repeated in group metadata.

`AgentMemory` callers must use its methods rather than its embedded low-level
Oracle. A direct `memory.oracle.sprout()` cannot join the payload/contract
transaction. Diagnostics compare lifecycle, payload, and protected-contract ID
sets, report the adapter unhealthy if a caller creates an unpaired vine, and
refuse to use that vine as Contextual Logic evidence.

Exact retries are deduplicated with a keyed content digest. Deletion removes
the managed record and writes an authenticated tombstone. The payload database
uses WAL, `synchronous=FULL`, foreign keys, strict schema-object validation,
unique `(key_id, nonce)` indexes, and cross-table nonce-reuse detection.
Each writable `AgentMemory` instance holds one profile-wide SQLite lease.
Bundled long-lived MCP transports open and close an instance per tool call;
Algo CLI does so per memory operation, and native fresh-process adapters close
at process exit. A direct SDK caller must close its instance explicitly.

## What local protection covers

- Memory topic and content at rest in the scoped-v2 payload database.
- Semantic-layer identity, provenance, expiry/review timestamps, ordered
  promotion evidence, and Contextual Logic relationships at rest.
- The current Live payload and every changed Live version. Same-content refresh
  rewrites only the record-bound encrypted expiry/provenance contract; changed
  content creates a separately encrypted superseding record.
- Lifecycle anchors and retrieval embeddings at rest.
- Lexical features, which are stored as keyed hashes rather than words.
- Topic metadata, which is stored as an opaque keyed token and verified against
  the authenticated encrypted record before it can support result grouping.
- Record and vector integrity, including scope/record/schema/key binding.
- Fail-closed contract integrity: a missing, transplanted, corrupt, or
  unauthenticated layer contract is never replaced by plaintext defaults.
- Bounded Contextual Logic traversal: roots keep normal confidence gates and
  linked evidence is explicitly marked as authenticated relationship evidence,
  not an independently query-scored result.
- Bounded competing-memory signals: the strongest authenticated same-topic
  current pair is preserved without silently selecting or inventing a winner.
- Ordinary Algo CLI writes when Algo is explicitly configured with
  `echo_veil_protection=required`.

## Metadata that remains visible

The local database still exposes opaque record IDs, an opaque random scope ID,
non-secret key IDs, schema versions, vector dimensions/counts, operation state,
timestamps, supersession relationships, row counts, database size, and access
patterns. An attacker may infer activity and relationship patterns even though
the content, topic, semantic layer, provenance, contextual links, vectors, and
lexical terms are not readable. Record IDs remain visible individually, but the
related-ID list that creates a Contextual Logic edge is inside ciphertext.
Authorized context responses necessarily reveal the selected roots, returned
links, and linked records to the caller; Echo Veil does not persist a separate
plaintext relationship index.

## What local protection does not cover

- Plaintext while Python, NumPy, SQLite, or the embedding process is using it.
  Python cannot guarantee complete zeroization.
- Authorized output returned to the caller or content the caller adds to model
  context, logs, traces, crash reports, action receipts, or conversation
  history.
- Harness documents, wiki pages, graph records, curated memory, transcripts,
  or other application stores that do not use `AgentMemory`.
- Transport to a caller-supplied remote embedder or model. Bundled adapters use
  loopback-only Ollama, but the embedding service receives plaintext.
- Host compromise, malicious code running as the profile owner, kernel/storage
  compromise, screen capture, swap, hibernation, or forensic recovery.
- Physical erasure from storage media, WAL history, snapshots, or backups.
- Availability after every referenced key is lost.
- Hardware isolation, homomorphic computation, or proof-gated access. Those
  require the separately provisioned enclave profile.

Temporary files are not used for payload content. Key-manifest replacement uses
an owner-only temporary file containing references and non-secret metadata. On
Windows, the temporary file is created with a protected current-user/System
DACL before bytes are written, flushed in binary mode, and published with a
same-volume `MoveFileExW` replace plus write-through. Echo Veil keeps the entire
drive-root-to-profile ancestry open without delete sharing during publication
and verifies the published handle's exact bytes, final path, regular-file type,
single-link identity, owner, and DACL. UNC profile roots are rejected because
this local boundary cannot pin their namespace authority.

Windows profile directories are created or canonicalized to a protected,
inheritable current-user/System DACL before key or database bytes are created.
Raw key files and the main SQLite files also receive a protected DACL at native
creation time; WAL, shared-memory, and rollback-journal files inherit the same
private directory boundary. A pre-existing profile leaf is canonicalized only
through a no-delete-share handle when its owner is the current user; trusted
Windows service owners are accepted only for immutable ancestry. Unsafe leaf
owners, reparse points, replaceable ancestry, and pre-existing broad files fail
closed. A standalone `SQLiteStore` creates a missing dedicated parent privately,
but never canonicalizes an existing caller-supplied parent: that directory must
already satisfy the exact private DACL or the open fails. On POSIX, the existing
boundary now validates the current UID as well as mode bits, pins every trusted
directory edge with no-follow descriptors, rejects replaceable ancestry and
multi-link security files, opens children relative to the pinned parent, and
revalidates namespace identity after use. Key manifests are staged and
published relative to that same parent, then checked for exact inode and bytes
before the directory is synced. Main SQLite files and published WAL/SHM/journal
sidecars use the same owner, mode, identity, and single-link checks. A dedicated
private parent is required; Echo Veil does not silently repair an unsafe
caller-owned POSIX directory.

The local ANN derivation is independently versioned as `echo-veil-lsh-index-v2`.
Projection seeds are derived from the profile LSH key and vector dimension, and
the raw projection buckets are transformed into fixed-size HMAC-SHA256 tokens
before SQLite persistence. A second keyed tag binds each token to its record and
band, including protected records that a generic store cannot reveal. Index-key
or derivation drift triggers a protected rebuild. This prevents an
unauthenticated copied bucket table from being trusted
and prevents raw cross-profile bucket correlation; it does not hide equality
within one profile, query/access patterns, corpus size, or approximate-neighbor
structure.

SQLite may create WAL and shared-memory files; payload-bearing database pages
remain encrypted at the record level. Backups must include the database,
lifecycle store, key manifest, and referenced keys as one protected recovery
set. Echo Veil does not yet provide a qualified backup/restore command.

## Record-envelope v3 migration

The database security contract remains `scoped-v2`, independently of the
encrypted record format. Existing profiles start as v2 reader/writers. An
operator-only, confirmed migration installs a persistent activation marker,
switches new writes to record-envelope v3, and converts lifecycle anchors,
payloads, vectors, contracts, keyed metadata, integrity tags, and tombstones in
bounded batches. V2 and v3 records are both readable while migration is in
progress, and the next writable open completes an interrupted activation before
an Oracle can write.

V3 derives purpose-specific keys with HKDF-SHA256 from the profile root. Every
derivation authenticates the normalized profile scope, opaque scope ID, key
epoch, purpose, envelope version, and algorithm. A payload ciphertext therefore
does not authenticate under the vector, semantic-contract, token, integrity,
or backup domain. The root remains file-backed in the current implementation,
so this separation does not protect plaintext or keys after trusted-host
compromise.

The authenticated key-manifest feature is also a one-way write-version floor.
Once that feature is present, a live database edit cannot switch new writes
back to envelope v2. Prepared, migrating, and verified states are checked
against their allowed write version and stored-version counts; false
verification, a late v2 write, and cross-profile ciphertext transplantation
fail closed. Local-production readiness also counts remaining v2 lifecycle
anchors instead of trusting the migration-state label alone.

The activation marker is also a downgrade barrier. A pre-v0.8 core must reject
the unknown manifest/schema instead of returning an apparently empty profile.
Returning to that core requires restoring a verified pre-migration recovery
set. Harnesses never see this format: their RPC and receipt remain
`preflight_v2` and `echo-veil-preflight-v2`.

## Key custody and rotation

`keyring.json` contains only non-secret key references. Raw 32-byte keys live in
owner-only files under `keys/`; scoped-v2 configuration never stores a raw key.
Symlinked paths, missing keys, mismatched key IDs, and group/world-readable
security files fail closed. Windows applies and revalidates the equivalent
owner/trusted-only DACL rather than relying on mode bits that older CPython
versions ignore.

After four-layer migration, the key manifest carries a non-secret
`shielded-four-layer-v1` feature marker inside the profile scope binding. This
prevents deleting the database contract marker and all contract rows from being
misread as a pre-migration profile. A normal writable open can finish the safe
crash window where database migration committed before the manifest marker;
read-only degraded recall cannot.

Rotation is explicit, bounded, resumable, and idempotent:

1. A new active key is created; new writes use it immediately.
2. The previous key remains decrypt-only.
3. Each confirmed rotation call rewraps a bounded batch of payloads, semantic
   contracts, retrieval vectors, lifecycle anchors, keyed terms, and tombstones.
4. Rotation becomes `verified` only when no managed object references the old
   key and no record is quarantined.
5. Retirement requires a separate confirmation that old-key backups have been
   accounted for.

Losing a referenced key is a hard initialization error. It is never reported
as an empty profile. Retirement cannot guarantee physical erasure of key bytes
from snapshots, backups, storage media, or process memory.

Migrating from `file-v1` to the reviewed macOS custody provider is a separate
two-process operation. The migration process may import and verify the root but
must retain the owner-only file copy. Activation writes a root-authenticated
receipt bound to a random process-instance nonce. Reopening an object in that
same process does not satisfy the gate: file custody can be retired only after
a different process has reopened the profile through the pinned helper,
derived the expected purpose keys, and completed protected recall. Retirement
is restart-resumable if descriptor publication succeeds before raw-file
removal. This prevents one compromised or faulty migration process from both
installing and immediately destroying the only independently recoverable root
copy.

`local-best-effort` rollback detection advances a separately held custody
generation after each authenticated backup. Once a newer generation exists,
verification, dry-run restore, and actual restore reject an older snapshot.
This detects stale restores only while the device-bound custody item and its
generation remain trustworthy; it is not equivalent to an external monotonic
authority or protection from whole-device rollback.

## Corruption behavior and diagnostics

Authentication failure on a payload or retrieval vector quarantines that
record, excludes it from recall, and leaves healthy records available. Global
schema, foreign-key, nonce-reuse, writer-lease, or keyring failures stop the
profile because continuing would make the trust boundary ambiguous.
Diagnostics expose fixed reason classes and counts, not plaintext, search
terms, ciphertext, raw keys, scope values, or filesystem paths.

`echo_veil_doctor` reports the local security schema, non-secret active key ID,
quarantine and tombstone counts, rotation state, protected-index backlog, and
these independent readiness facts:

- `installed`
- `enabled`
- `crypto_initialized`
- `write_wired`
- `index_wired`
- `retrieval_wired`
- `persistence_wired`
- `restart_restored`
- `layer_contract_wired`
- `context_trace_wired`
- `rotation_ready`
- `healthy`

The embedding host must separately report `version_supported`; the Echo Veil
adapter cannot prove the application installed the intended distribution.
`healthy=true` means the local scoped-v2 path opened and reconciled cleanly. It
does not mean the production enclave is deployed or externally reviewed.

## Application entry-point classification

Every host must publish its own matrix. For the Algo CLI integration, the
contract is:

| Entry point | Protection-required mode | Optional mode |
|---|---|---|
| `/remember`, direct runtime remember, bounded automatic fact capture | Echo Veil scoped-v2 only; unavailable crypto blocks the write | Echo when healthy; otherwise the explicitly warned legacy path |
| Live → Short-Term and Short-Term → Long-Term promotion | Echo Veil protected contract only; reason required and ordered history retained | Same Echo contract; no external plaintext promotion |
| Live refresh | Unchanged state renews only encrypted expiry/provenance; changed state creates an encrypted superseding record | Same Echo contract; unavailable in degraded read-only mode |
| Associative recall and semantic-layer filtering | Echo only; no plaintext-memory fallback or score rewriting | Echo when healthy; legacy fallback is allowed and identified |
| Contextual Logic support trace | Confidence-checked Echo roots plus bounded authenticated outgoing links; linked evidence is not query-scored | Same Echo trace when healthy; degraded keyed roots remain explicitly non-semantic |
| `/forget` | Echo deletion plus authenticated tombstone; dependent Contextual Logic records are deleted transitively | Active backend's deletion behavior |
| External curated/history promotion, demotion, archive, and reindex commands | Prohibited because those stores are outside Echo | Deliberately plaintext under their existing policy |
| Full harness, wiki, graph, lessons, transcript, and session-history source writes | Deliberately outside Echo; no protection claim. Only a bounded current transcript may temporarily enter protected Live memory | Deliberately outside Echo; no protection claim |
| Legacy imports and migrations | Explicit operator workflow only; no silent import | Explicit operator workflow only |

Compatibility commands must call the same authoritative Algo bridge. A second
Oracle wrapper or plaintext `echo_veil_state.json` is prohibited.

For Pi, the native extension treats preflight as a model-execution gate, not
optional prompt guidance. It validates the scoped-v2 doctor state, recalls at
least two candidates, adds bounded Contextual Logic where required, rechecks
expanded prompts, and injects authenticated results only as untrusted evidence.
Input failure stops normal model startup; non-input agent starts without a
successful preflight are aborted, and tools are blocked outside the authorized
run. Mid-run steer/follow-up is rejected instead of entering an already-running
loop without fresh evidence.

Hermes uses two distinct host surfaces because its observer hooks are
fail-open by design. `pre_llm_call` produces bounded ephemeral protected
context and records an exact session/task/turn attestation.
`llm_execution` is the enforcement boundary: without that attestation it
and its random per-turn nonce in the effective provider request, it returns a
generic zero-usage blocked response and never invokes the provider.
For singular mutable-memory mode, both `memory.memory_enabled` and
`memory.user_profile_enabled` must be false. Hermes general plugins are opt-in,
and plugin import or registration failure does not abort host startup, so a
loaded-plugin check and an installed zero-provider outage smoke are mandatory
operational gates after every Hermes update.

`echo-veil-shielded-run hermes --model MODEL` provides a separate hard
headless boundary. It completes protected semantic preflight before process
creation, validates the installed plugin against digests embedded in the Echo
build, copies only those reviewed bytes into a temporary owner-only
`HERMES_HOME`, writes a fixed native-memory-off configuration, and binds the
prompt to a random launch nonce. The plugin registers the dedicated
`echo-veil-run` CLI command only after all required hooks and middleware.
Registration failure therefore makes the command unavailable before any model
path exists. One loopback Ollama provider and the Echo MCP toolset are the only
qualified capabilities; ambient Hermes configuration, sessions, memories,
skills, and plugins are not exposed. This does not broaden the claim to normal
plugin mode, gateways, interactive sessions, or arbitrary Hermes toolsets.

OpenClaw qualifies a hard pre-model gate only when Echo owns the exclusive
memory slot, both required Echo hook permissions are true, and each protected
model is pinned to `agentRuntime.id="openclaw"`. Its built-in
`session-memory` hook must also be explicitly disabled; the Echo plugin checks
the slot, permissions, and native-memory setting before attempting protected
recall. The plugin binds a successful prompt-build injection to a random,
expiring, single-use attestation checked by `before_agent_run`. OpenClaw's
native Codex app-server runtime does not run the complete gate and must not be
used for a singular-authority claim.

Codex and Claude Code use plugin-bundled `UserPromptSubmit` and
`PreToolUse(Agent)` hooks. Codex installation does not trust command hooks:
review both exact definitions in `/hooks`, and repeat review after every hash
change. Codex native memories must be disabled separately. The installed Codex
collaboration router bypassed `PreToolUse`, so direct subagents are outside the
claim. `echo-veil-shielded-run codex` provides a separate headless root
boundary: it preflights before process creation, ignores ambient user config,
uses a temporary owner-only Codex home that exposes only the validated auth
handle, requires one Echo MCP server, disables native memory and parallel
agents, and defaults to a read-only ephemeral run. Claude Code must run in normal plugin
mode with auto-memory disabled;
`CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` is the auditable process control.
`--safe-mode` and `--bare` disable the boundary. Droid packages equivalent root
and `PreToolUse(Task)` hooks through an absolute executable wrapper, but Droid
0.180.0 `exec` did not invoke them. Bare `droid exec` is therefore outside the
claim. `echo-veil-shielded-run droid` preflights before process creation and
disables `Task`; interactive hooks and managed-hook deployments remain separate
qualification targets. Direct or future spawn paths that bypass a supported
tool hook remain outside the claim.

Goose's normal recipe is policy-driven. `echo-veil-shielded-run goose` is the
hard headless boundary: it preflights before host creation and uses
`--no-profile`, `--no-session`, one explicit Echo extension, and at most the
reviewed `developer` builtin.

OpenCode uses a global or project plugin that runs protected recall during
`chat.message`, binds success to the current message ID, and requires that
binding at `chat.params` before provider assembly. Its supported `Task` tool
path is preflighted and rewritten before execution, and automatic
post-compaction continuation is disabled. `--pure` disables external plugins
and is outside singular-authority mode. The normal installed root path has a
zero-assistant-message, zero-token, zero-cost forced-outage smoke; the installed
Task path remains a separate release qualification.

Mercury cannot enter required singular-authority mode under its current host
contract. Disabling Second Brain falls back to a native Long-Term store and
does not remove the separately constructed Short-Term or Episodic stores. The
bundled Mercury skill is doctor-only and must not mutate host configuration or
transport payloads through the shell.

## Promotion and release gate

Neither `healthy` nor a successful local test may be renamed
`production_ready`. A release may promote the integration only when CI and
review evidence covers:

- the supported Echo package in the actual Algo runtime;
- protection-required fail-closed behavior;
- ordinary write, protected disk state, authorized scope recall, and a fresh
  process restart;
- absence of plaintext in the store, index, temporary artifacts, and captured
  diagnostics;
- all four semantic layers using authenticated record-bound contracts, including
  tamper/missing-contract, promotion-order, expiry, relationship, cascade-delete,
  layer-filter, bounded context-trace, degraded-read, migration, and key-rotation
  tests;
- bounded seed-crystal enforcement, transcript rejection outside Live, explicit
  changed-content supersession, same-content protected renewal, and degraded
  refresh rejection;
- corruption isolation, concurrent-writer rejection, interrupted-write
  reconciliation, and lost-key behavior;
- completed and restart-safe rotation;
- a qualified backup/restore and rollback exercise;
- an explicit status for every memory-writing entry point;
- dependency, license, privacy, and security gates;
- acceptable measured write/recall overhead; and
- independent review of this threat model and the release diff.

The current repository provides implementation and automated evidence for most
of the local data path. A published, lockable package artifact, qualified
backup/restore exercise, actual host-runtime installation test, and independent
security review remain release blockers until separately recorded.
