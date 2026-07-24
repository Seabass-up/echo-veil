# Architecture Notes

This document records what was built, where it departs from the spec, the
assumptions made, and the known risks. It exists so that no part of the system
is trusted for more than it actually does.

## 1. Scope decisions

The spec (`SPEC.md`) is a strong *design* document: it names components, gives
topology, and fixes several numeric thresholds. It is **not** a complete
engineering specification — it omits some formulas, protocol details, and a
threat model. This implementation builds the parts that are well-defined enough
to implement faithfully, and is explicit about the parts that are not.

Implemented and tested:
- Tiered storage interfaces (L1 active workspace; L2 metadata index; L3 cold
  archive), with both in-memory reference backends and a durable transactional
  SQLite L1/L2/L3 backend.
- The decay loop: proximity scoring, twilight demotion, eviction, amber locks,
  multi-focal crests, and the tidal-flow cache split.
- The confidence spectrum matrix with generation gating.
- The data tension protocol: conflict vines, peer-review zone, fossilization,
  and the Lazarus resurrection loop.
- Intent drift detection with a moving-average centroid and hysteresis.
- The Gardener's Report.
- A practical AES-256-GCM Crypto Shield for encrypted/authenticated protected vectors.
- The capability/doctor report for defensive readiness and production-gap visibility.
- Internal twilight cycle tracking (the workspace counts decay cycles itself,
  removing the caller-supplied footgun).
- Evicted vine pruning (no memory leak in the workspace dict).
- Boundary validation for finite/non-empty vectors, stable dimensions,
  configuration, timestamps, scores, archive/index inputs, and lifecycle calls.
- Retry-safe eviction transfer: failed L2/L3 writes leave vines pending rather
  than pruning unarchived state.
- Atomic SQLite eviction commits, crash recovery, restart search, protected
  payload reconstruction, and durable topic/lifecycle metadata.
- Transactional active-workspace checkpoints and startup restoration, including
  twilight counters, Amber Locks, and focal crests.
- Fail-closed per-vine deletion across managed L1/L2/L3 state, with durable
  transaction rollback and best-effort release of material on live Vine objects.
- Persisted random-projection LSH candidate lookup with exact reranking.
- A fail-closed CKKS enclave provider boundary with attestation policy and a
  zero-knowledge access-proof exchange.
- A deployable Azure AMD SEV-SNP origin using OpenFHE CKKS at the 128-bit
  classic security level, with end-to-end request envelopes, one-time
  challenges, expiring sessions, replay defense, and fail-closed configuration.
- A Ristretto255 Schnorr proof-of-possession helper using Merlin transcripts,
  public-key allowlisting, context binding, and owner-only identity keys.
- Reproducible Azure Bicep, Cloudflare OpenTofu/Worker, Caddy mTLS, container,
  key-generation, and deployment-runbook artifacts for `algo-cli.com`.
- Reentrant locking around Oracle, Workspace, MetadataIndex, ColdArchive, and
  DriftDetector operations.
- Automatic return-to-topic scoring and reinforcement for twilight vines.
- A concrete local `AgentMemory` host adapter with caller-selected embeddings,
  record/scope/schema/key-bound AES-GCM protected anchors, payloads, topics, and
  retrieval vectors; keyed minimal lexical metadata; exact-write
  deduplication; authenticated tombstones; startup reconciliation; resumable
  key rotation; record quarantine; confidence-gated active/cold recall;
  ambiguity telemetry; and a read-only keyed availability floor for local
  embedding outages.
- A bounded stdio MCP server for Codex, Claude Code, Hermes, OpenCode, Droid,
  and Goose, plus native OpenClaw and Pi packages. Every full adapter shares the
  same `AgentMemory` policy instead of reimplementing lifecycle rules per host.
- A Mercury readiness skill that reports the local boundary only. Mercury's
  documented skill interface does not expose a safe structured custom-tool
  transport, so remember, recall, and forget are deliberately unavailable.

Implemented as a practical confidentiality baseline:
- `AesGcmCryptoShield` encrypts/authenticates protected vectors with AES-256-GCM and loads keys from explicit bytes or `ECHO_VEIL_CRYPTO_KEY`.

Deployment-provided:
- The Azure subscription/quota, actual SEV-SNP VM, approved launch measurement,
  Key Vault Secure Key Release operation, Cloudflare Access audience/team,
  mTLS certificate registration, secrets, DNS, and independent production
  approval. Repository code cannot claim hardware isolation until those
  external controls have been provisioned and verified.

## 2. Assumptions made explicit

1. **Proximity Score formula (Section 2).** The spec references the formula
   but its equation block is empty in the preserved document. The implemented
   formula in `proximity.py` is:

   ```
   proximity = cosine_similarity(I, A) + 0.15 * exp(-Δt / 12)
   ```

   where I is the current intent vector, A is the vine anchor vector, and
   Δt is hours since the vine was last touched. The time constant 12 hours
   is taken verbatim from the spec's Section 2 description.

   - The cosine similarity term captures thematic relevance.
   - The additive recency term (0.15 at Δt=0, decaying to ~0 at large Δt)
     gives every vine a small score from recency alone, independent of cosine.
   - Score range: approximately (-1, 1.15]. Negative cosine values are NOT
     clamped, so the twilight threshold (0.42) implicitly requires some
     thematic alignment — a vine with cosine=-1 can never score above 0.15.
   - The time constant (12h) is exposed via `ProximityConfig` for tuning.
     **This is our choice for the decay rate, not the spec's** — the spec
     names the formula but not the time constant value.

2. **Embedding model is out of scope.** Anchor/intent vectors are inputs. The
   spec assumes 768 dimensions; the code does not hard-code that so you can use
   any model. Each Oracle/Workspace does require one stable, finite, non-empty
   vector dimension for its lifetime. Vector quality dominates real-world
   behavior and is the responsibility of the caller.

3. **Twilight cycle counting is internal.** The spec says "5 query cycles or
   30 minutes, whichever is longer." The workspace now tracks cycle counts
   internally via `_twilight_cycles`. Callers can still override via the
   `cycles_since_twilight` parameter, but it is no longer required for correct
   eviction behavior — the internal counter is the default.

4. **The core has no implicit embedding dependency.** `HashingTextEmbedder`
   remains a deterministic offline test fixture and keyword-oriented fallback;
   it is not evidence of semantic quality. Bundled full adapters explicitly use
   loopback-only Qwen3 embeddings, pin their identity inside each profile, and
   must benchmark the real corpus. Caller-supplied embedders are separate trust
   boundaries and may receive plaintext.

## 3. Deviations from the spec

| Spec statement | What we did | Why |
|---|---|---|
| "88% memory footprint compression" | Compress with zlib; report the *achieved* ratio; zero the anchor array during TWILIGHT | Real ratios depend on payload entropy; asserting a fixed number would be fiction. Zeroing the anchor prevents the original double-memory bug. |
| "< 5ms global lookup latency" | SQLite uses persisted random-projection LSH plus exact candidate reranking; no universal latency guarantee | Latency depends on corpus, dimensions, bucket collisions, and storage hardware. |
| "Exabyte-viable data horizon" (L3) | In-memory reference store or durable local SQLite | SQLite is crash-safe local persistence, not exabyte-scale object storage. |
| Practical encrypted vector protection | `AesGcmCryptoShield` with AES-256-GCM | Provides confidentiality/authentication for protected vector payloads, with transient decrypt for similarity. |
| Homomorphic / enclave / zk-SNARK shield | OpenFHE CKKS in an Azure SEV-SNP VM plus a Ristretto255 Schnorr possession proof | The spec provides no SNARK circuit or statement. The selected proof has no trusted setup and proves allowlisted key possession; Cloudflare posture separately handles operator devices. |
| Confidence bands gate generation | Implemented `Oracle.check_generation_gate()` with `GenerationGated` exception | Originally the `gates_generation` flag was defined but never enforced. Now INFERENTIAL requires explicit override and OBSCURITY is a hard stop. |
| Evicted vines remain in workspace dict | Evicted vines are pruned after L2/L3 archiving via `Workspace.prune_evicted()` | Original code leaked evicted vine objects forever. The Oracle now archives first, prunes only written IDs, and retries pending evictions after backend failures. |
| Production starts with AES-GCM, `NullCryptoShield`, or an arbitrary readiness marker | Rejected | Production requires `EnclaveCryptoShield` specifically. AES-GCM remains a development/staging encrypted-storage baseline. |
| Custom protected payload cannot be archived | Reject the sprout | Silently retaining and archiving the plaintext anchor would violate the caller's confidentiality intent. Protected payloads must provide `to_json_bytes()`. |

## 4. Risks and tradeoffs

- **Tuning risk (medium).** Behavior is sensitive to `time_constant_hours` and
  `pressure_evict_at`. Defaults are reasonable but unvalidated against real
  traffic. Recommend logging proximity-score distributions before trusting
  eviction in production.
- **Storage scale (deployment-dependent).** `SQLiteStore` provides durable,
  atomic local L1/L2/L3 state, restart recovery, and indexed LSH retrieval. Its
  capacity is bounded by a local filesystem. Deployments needing distributed
  storage or a different recall/latency tradeoff should implement the same backend
  contracts with an appropriate database/object store.
- **L1 has a durable checkpoint.** With `SQLiteStore`, active and twilight vines,
  cycle counters, locks, and crests are restored at Oracle startup. The live
  computation copy remains in memory, while SQLite is the restart source of truth.
- **Confidence scores are inputs.** The matrix classifies a score it is given;
  it does not compute retrieval confidence. Garbage in, garbage out.
- **Thread safety (reduced, not eliminated).** Core Oracle, Workspace, index,
  archive, and drift operations are serialized with reentrant locks. Publicly
  returned `Vine` objects are still mutable outside those locks. `SQLiteStore`
  coordinates L2/L3 writes across processes, but L1 objects remain process-local;
  other backend implementations must provide equivalent coordination. Use the
  public mutation methods rather than editing returned Vines concurrently.
- **Managed deletion is not physical erasure.** `Oracle.forget()` coordinates
  deletion of one vine across Echo Veil's managed tiers, and SQLite enables
  `secure_delete`. Host payloads, conflict/fossil records, WAL remnants,
  backups, and storage-media retention remain deployment responsibilities.
- **Custom crypto shields are not automatically trusted.** The Oracle rejects
  objects that do not implement `protect()` and `similarity()`, rejects
  non-serializable protected payloads, and requires an explicit readiness marker
  for custom shields in staging. A marker cannot prove cryptographic strength;
  capability reporting keeps custom shields degraded until their design,
  serialization behavior, and threat model are reviewed outside Echo Veil.
- **Host-plugin overlap is intentional but bounded.** Every host gets a distinct
  profile by default, and the adapters expose opt-in tools rather than automatic
  prompt injection. The OpenClaw integration does not take its configured
  memory slot or context engine. This prevents duplicate automatic recall with
  `memory-core`, Active Memory, or Lossless Claw. A future automatic hook must
  define precedence, tenant boundaries, latency budgets, and deduplication
  before activation. Writable adapter processes hold a profile-wide SQLite
  lease for their lifetime; concurrent callers wait only for the configured
  bounded timeout and then fail closed.
- **The local availability layer is degraded recall, not a crypto or semantic
  fallback.** It opens only an existing owner-protected payload database in
  SQLite read-only mode, uses subject-masked keyed term overlap, and returns a
  fixed degraded marker. Qualified raw overlap is mapped only into the
  non-authoritative Fragmented Synthesis band and can never claim Coherent or
  Solid confidence. It cannot write, forget, reindex, lower its calibrated
  threshold, perform inferential recall, or mutate lifecycle state. Only local
  Ollama service/model unavailability activates it; integrity, identity, key,
  schema, and malformed-response failures remain hard stops.
- **Local scoped-v2 metadata is minimized, not invisible.** Payloads, topics,
  lifecycle anchors, and retrieval vectors are encrypted; lexical terms and
  topics are keyed opaque values. Record IDs, random scope IDs, key IDs,
  schema/dimension data, timestamps, supersession shape, counts, sizes, and
  access patterns remain visible. Plaintext exists in the authorized process
  and loopback embedding service. Logs, model context, host stores, swap,
  snapshots, backups, and physical media are outside this adapter's protection
  unless separately controlled.

## 5. Crypto shield: trust boundary

The spec's Section 5 composes three independently difficult technologies:
CKKS homomorphic encryption, a hardware enclave (SGX / SEV-SNP), and a zk-SNARK
attestation gate. The spec provides naming and topology but **no protocols,
parameters, key-management story, or threat model.**

A practical baseline and the Level-5 integration boundary are implemented:

- `AesGcmCryptoShield` — practical AES-256-GCM protected vectors. It encrypts and authenticates anchor-vector payloads, supports random 256-bit keys, base64 environment-variable loading, and tamper detection. When an Oracle is constructed with this shield, newly sprouted active vines store a protected anchor and release the plaintext anchor array; decay scoring uses shield-backed transient decrypt inside `similarity()`. Encrypted evictions are archived as ciphertext payloads and are not inserted into the plaintext reference L2 index. This does not provide homomorphic computation or enclave isolation.
- `NullCryptoShield` — dev/test only, pass-through, **no confidentiality**,
  warns on construction.
- `EnclaveCryptoShield` — obtains fresh provider evidence, delegates verification
  to the deployment trust root, enforces fresh attestation, at least 128-bit CKKS
  security, hardware isolation, homomorphic similarity, and a ZKP access gate,
  then exchanges the proof for an opaque session. Vectors remain opaque CKKS
  ciphertexts in the Python process.
- `Oracle(environment="production")` — requires `EnclaveCryptoShield`
  specifically. Staging accepts AES-GCM or an explicitly staging-ready custom
  shield, but capability reporting keeps AES/custom shields blocked for
  production.
- `Oracle.capability_report()` / `doctor_report()` — returns JSON-serializable readiness status for crypto, storage, vector index, persistence, thread safety, confidence gating, warnings, and production blockers.

The included deployment supplies the concrete pieces:

1. `CloudflareEnclaveProvider` plus the Worker/mTLS path for transport.
2. `echo_veil_origin` with OpenFHE CKKS, normalized signed evidence, secure
   envelopes, sessions, and replay defense on an Azure confidential VM.
3. `RistrettoSchnorrProofProvider` and `echo-veil-zkp` for the proof gate.

Real trust still begins only after Azure Key Vault releases the attestation key
under a policy bound to the approved SEV-SNP measurement and the client installs
the matching public key/measurement allowlist.

### Cloudflare gateway

The included Worker places Cloudflare Access in front of the provider protocol,
validates the Access JWT issuer/audience/signature, accepts only the five POST
endpoints, bounds request/response sizes, disables caching, and calls the
enclave origin through a Worker mTLS binding plus an origin bearer secret. The
Python `CloudflareEnclaveProvider` uses the documented Access service-token
headers and bounded HTTPS responses. The attested X25519 key seals all
post-attestation bodies end to end, so Cloudflare routes opaque envelopes rather
than vector or proof plaintext. The downstream vendor evidence is still
verified locally by the configured `AttestationVerifier`.

## 6. Durable storage behavior

`SQLiteStore` is the built-in production persistence path for a local process or
small multi-process deployment:

- L1 checkpoints, L2 index rows, L3 payloads, and eviction metadata use
  transactions. L2/L3 eviction records commit inside one
  `BEGIN IMMEDIATE` transaction. Any failure rolls the complete batch back and
  the Oracle leaves affected vines pending for retry.
- WAL mode, `synchronous=FULL`, a busy timeout, and SQLite locking provide crash
  recovery and cross-process writer serialization.
- The executable adapter adds a profile-wide writer lease before loading L1 and
  reconciles lifecycle/payload ID sets at startup. Interrupted lifecycle-first
  remembers are removed safely; unexplained encrypted payload orphans are
  preserved and block startup for operator review.
- `Oracle.forget()` uses one `BEGIN IMMEDIATE` transaction to remove matching
  active, index, archive, ANN, and eviction-metadata records. Failures roll back
  before a live Vine is released, allowing the caller to retry.
- Database files are created with owner-only permissions, versioned with
  `PRAGMA user_version`, and checked with `PRAGMA quick_check` and
  `foreign_key_check` on open by default. Expected tables, indexes, columns,
  and foreign-key definitions are validated so injected triggers or altered
  indexes fail closed. Unknown future schema versions fail closed.
- Built-in AES and enclave payloads are reconstructed through the algorithm-aware
  protected payload loader. Custom shields may supply a compatible loader.
- The SQLite index reports `search_strategy="lsh-ann"`. Eight indexed bands of
  random-projection signatures select candidates, and the exact scorer reranks
  only those rows. Version-1 databases migrate to version 2 and backfill all
  plaintext index rows.
