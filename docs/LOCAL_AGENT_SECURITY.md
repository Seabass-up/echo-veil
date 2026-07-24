# Local agent-memory security contract

This document defines the security boundary of
`echo_veil.agent_memory.AgentMemory`. The adapter is a local staging security
subsystem. It is not the attested production enclave described in
[`DEPLOYMENT_THREAT_MODEL.md`](DEPLOYMENT_THREAT_MODEL.md), and an importable
package or enabled feature flag is not evidence that an application uses it.

## Protected path

For a scoped-v2 profile, one ordinary remember operation follows this sequence:

1. Validate and bound the topic, payload, identifiers, timestamps, and vectors.
2. Bind the profile to one normalized authorization scope.
3. Serialize the topic and payload into a versioned record envelope.
4. Encrypt the envelope and each retrieval vector independently with
   AES-256-GCM and a fresh 96-bit nonce.
5. Authenticate the object type, opaque scope ID, record ID, schema version,
   key ID, and vector ordinal/dimension as associated data.
6. Commit the encrypted payload, protected vectors, and keyed lexical features
   as one `pending` SQLite transaction.
7. Persist the Echo Veil lifecycle anchor under the same stable record ID.
8. Mark the payload record `committed`.

Startup reconciles the only two safe interrupted states. A pending payload with
matching lifecycle state is committed; a pending payload without lifecycle
state is removed. Lifecycle state without a payload is forgotten. An
unexplained committed payload orphan is preserved and blocks startup for
operator review. Recall considers only committed, non-quarantined records,
decrypts after candidate selection, and checks the profile scope binding before
opening either database.

Exact retries are deduplicated with a keyed content digest. Deletion removes
the managed record and writes an authenticated tombstone. The payload database
uses WAL, `synchronous=FULL`, foreign keys, strict schema-object validation,
unique `(key_id, nonce)` indexes, and cross-table nonce-reuse detection.
Writable processes hold one profile-wide SQLite lease.

## What local protection covers

- Memory topic and content at rest in the scoped-v2 payload database.
- Lifecycle anchors and retrieval embeddings at rest.
- Lexical features, which are stored as keyed hashes rather than words.
- Topic metadata, which is stored as an opaque keyed token.
- Record and vector integrity, including scope/record/schema/key binding.
- Ordinary Algo CLI writes when Algo is explicitly configured with
  `echo_veil_protection=required`.

## Metadata that remains visible

The local database still exposes opaque record IDs, an opaque random scope ID,
non-secret key IDs, schema versions, vector dimensions/counts, operation state,
timestamps, supersession relationships, row counts, database size, and access
patterns. An attacker may infer activity and relationship patterns even though
the content, topic, vectors, and lexical terms are not readable.

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
an owner-only temporary file containing references and non-secret metadata.
SQLite may create WAL and shared-memory files; payload-bearing database pages
remain encrypted at the record level. Backups must include the database,
lifecycle store, key manifest, and referenced keys as one protected recovery
set. Echo Veil does not yet provide a qualified backup/restore command.

## Key custody and rotation

`keyring.json` contains only non-secret key references. Raw 32-byte keys live in
owner-only files under `keys/`; scoped-v2 configuration never stores a raw key.
Symlinked paths, missing keys, mismatched key IDs, and group/world-readable
security files fail closed.

Rotation is explicit, bounded, resumable, and idempotent:

1. A new active key is created; new writes use it immediately.
2. The previous key remains decrypt-only.
3. Each confirmed rotation call rewraps a bounded batch of payloads, retrieval
   vectors, lifecycle anchors, keyed terms, and tombstones.
4. Rotation becomes `verified` only when no managed object references the old
   key and no record is quarantined.
5. Retirement requires a separate confirmation that old-key backups have been
   accounted for.

Losing a referenced key is a hard initialization error. It is never reported
as an empty profile. Retirement cannot guarantee physical erasure of key bytes
from snapshots, backups, storage media, or process memory.

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
| Associative recall and context augmentation | Echo only; no plaintext-memory fallback | Echo when healthy; legacy fallback is allowed and identified |
| `/forget` | Echo deletion plus authenticated tombstone | Active backend's deletion behavior |
| Curated/history promotion, demotion, archive, and reindex commands | Prohibited because those stores are outside Echo | Deliberately plaintext under their existing policy |
| Harness, wiki, graph, lessons, transcript, and session-history writes | Deliberately outside Echo; no protection claim | Deliberately outside Echo; no protection claim |
| Legacy imports and migrations | Explicit operator workflow only; no silent import | Explicit operator workflow only |

Compatibility commands must call the same authoritative Algo bridge. A second
Oracle wrapper or plaintext `echo_veil_state.json` is prohibited.

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
