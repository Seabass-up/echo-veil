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
  archive). L2/L3 are in-memory reference implementations.
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

Implemented as a practical confidentiality baseline:
- `AesGcmCryptoShield` encrypts/authenticates protected vectors with AES-256-GCM and loads keys from explicit bytes or `ECHO_VEIL_CRYPTO_KEY`.

Not implemented (interface/stub only):
- The original Level-5 CKKS + hardware enclave + zk-SNARK shield (Section 5).

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
   any model. Vector quality dominates real-world behavior and is the
   responsibility of the caller.

3. **Twilight cycle counting is internal.** The spec says "5 query cycles or
   30 minutes, whichever is longer." The workspace now tracks cycle counts
   internally via `_twilight_cycles`. Callers can still override via the
   `cycles_since_twilight` parameter, but it is no longer required for correct
   eviction behavior — the internal counter is the default.

## 3. Deviations from the spec

| Spec statement | What we did | Why |
|---|---|---|
| "88% memory footprint compression" | Compress with zlib; report the *achieved* ratio; zero the anchor array during TWILIGHT | Real ratios depend on payload entropy; asserting a fixed number would be fiction. Zeroing the anchor prevents the original double-memory bug. |
| "< 5ms global lookup latency" | No latency guarantee; linear-scan reference index | L2 is a reference impl. Swap in an ANN index/vector DB for production. |
| "Exabyte-viable data horizon" (L3) | In-memory dict | Reference impl. Swap in an object store. |
| Practical encrypted vector protection | `AesGcmCryptoShield` with AES-256-GCM | Provides confidentiality/authentication for protected vector payloads, with transient decrypt for similarity. |
| Homomorphic / enclave / zk-SNARK shield | Interface + refusing stub | See section 5 below. |
| Confidence bands gate generation | Implemented `Oracle.check_generation_gate()` with `GenerationGated` exception | Originally the `gates_generation` flag was defined but never enforced. Now INFERENTIAL requires explicit override and OBSCURITY is a hard stop. |
| Evicted vines remain in workspace dict | Evicted vines are pruned after L2/L3 archiving via `Workspace.prune_evicted()` | Original code leaked evicted vine objects forever. Now the Oracle archives first, then prunes. |
| Production starts with explicit `NullCryptoShield` or invalid shield object | Rejected | Production mode now rejects missing shields, explicit `NullCryptoShield`, and objects that do not implement the shield contract. |

## 4. Risks and tradeoffs

- **Tuning risk (medium).** Behavior is sensitive to `time_constant_hours` and
  `pressure_evict_at`. Defaults are reasonable but unvalidated against real
  traffic. Recommend logging proximity-score distributions before trusting
  eviction in production.
- **Reference storage (high if shipped as-is).** L2/L3 are in-memory and do not
  persist or scale. They are correct for testing the lifecycle, not for
  production. The interfaces are the stable contract.
- **No persistence layer.** A process restart loses all state. Persistence was
  out of scope for the core; it belongs behind the L2/L3 interfaces.
- **Confidence scores are inputs.** The matrix classifies a score it is given;
  it does not compute retrieval confidence. Garbage in, garbage out.
- **Thread safety (low for dev, high for production).** Workspace._vines is a
  plain dict with no locking. Concurrent mutation will corrupt state. Add
  locking or single-thread the workspace access for any multi-threaded host.
- **Custom crypto shields are not automatically trusted.** The Oracle rejects
  objects that do not implement `protect()` and `similarity()`. Structurally
  valid custom shields can be used, but capability reporting marks them degraded
  until their cryptographic design, serialization behavior, and threat model are
  reviewed outside Echo Veil.

## 5. Crypto shield: status and path

The spec's Section 5 composes three independently difficult technologies:
CKKS homomorphic encryption, a hardware enclave (SGX / SEV-SNP), and a zk-SNARK
attestation gate. The spec provides naming and topology but **no protocols,
parameters, key-management story, or threat model.**

A practical baseline is now implemented, but it is intentionally not described
as the full Level-5 design:

- `AesGcmCryptoShield` — practical AES-256-GCM protected vectors. It encrypts and authenticates anchor-vector payloads, supports random 256-bit keys, base64 environment-variable loading, and tamper detection. When an Oracle is constructed with this shield, newly sprouted active vines store a protected anchor and release the plaintext anchor array; decay scoring uses shield-backed transient decrypt inside `similarity()`. Encrypted evictions are archived as ciphertext payloads and are not inserted into the plaintext reference L2 index. This does not provide homomorphic computation or enclave isolation.
- `NullCryptoShield` — dev/test only, pass-through, **no confidentiality**,
  warns on construction.
- `EnclaveCryptoShield` — raises `NotImplementedError` on construction for the unbuilt CKKS + enclave + ZK stack.
- `Oracle(environment="production")` — refuses to start without a structurally valid shield and rejects explicit `NullCryptoShield`. Unknown custom shields are not reported as fully ready without external validation.
- `Oracle.capability_report()` / `doctor_report()` — returns JSON-serializable readiness status for crypto, storage, vector index, persistence, thread safety, confidence gating, warnings, and production blockers.

A realistic phased path, if this layer is pursued:

1. **Threat model first.** Define exactly what each layer defends against
   (untrusted host? untrusted operator? offline disk theft?). The rest follows
   from this and cannot be skipped.
2. **At-rest + in-transit encryption** with standard primitives. Covers the
   most common threats at a fraction of the cost.
3. **Enclave-based confidential compute** (SGX DCAP or SEV-SNP) with a working
   attestation flow, if the host itself is untrusted.
4. **Homomorphic similarity** (OpenFHE / Microsoft SEAL) only if computing over
   ciphertext on an untrusted party is a hard requirement — it carries large
   performance costs and should be justified by the threat model.
5. **zk-SNARK attestation gate** last, and only if a specific verifiable-access
   requirement remains that steps 1–4 do not cover.

Recommendation: treat steps 2–3 as the practical target. Steps 4–5 are research
commitments, not a sprint.
