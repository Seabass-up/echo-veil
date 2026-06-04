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
- The confidence spectrum matrix.
- The data tension protocol: conflict vines, peer-review zone, fossilization,
  and the Lazarus resurrection loop.
- Intent drift detection with a moving-average centroid and hysteresis.
- The Gardener's Report.

Not implemented (interface/stub only):
- The Level-5 cryptographic root shield (Section 5).

## 2. Assumptions made explicit

1. **Proximity Score formula (Section 2).** The spec references the formula and
   says "Where I represents... and Δt is the elapsed time," but the equation
   itself is missing from the document. We define:

   ```
   proximity = max(0, cosine_similarity(I, A)) * exp(-lambda * dt)
   lambda    = ln(2) / half_life_hours
   ```

   - Cosine captures thematic relevance (the spec's stated primary driver).
   - The exponential time term encodes the "time-decay factor."
   - We clamp negative cosine to 0 so the published score lands in [0, 1],
     which is what the spec's thresholds (0.42, 0.85, ...) assume.
   - Half-life (default 6h) is exposed for tuning. **This is our choice, not
     the spec's** — revisit if the original formula is recovered.

2. **Embedding model is out of scope.** Anchor/intent vectors are inputs. The
   spec assumes 768 dimensions; the code does not hard-code that so you can use
   any model. Vector quality dominates real-world behavior and is the
   responsibility of the caller.

## 3. Deviations from the spec

| Spec statement | What we did | Why |
|---|---|---|
| "88% memory footprint compression" | Compress with zlib; report the *achieved* ratio | Real ratios depend on payload entropy; asserting a fixed number would be fiction. |
| "< 5ms global lookup latency" | No latency guarantee; linear-scan reference index | L2 is a reference impl. Swap in an ANN index/vector DB for production. |
| "Exabyte-viable data horizon" (L3) | In-memory dict | Reference impl. Swap in an object store. |
| Homomorphic / enclave / zk-SNARK shield | Interface + refusing stub | See section 5 below. |

## 4. Risks and tradeoffs

- **Tuning risk (medium).** Behavior is sensitive to `half_life_hours` and
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

## 5. Crypto shield: status and path

The spec's Section 5 composes three independently difficult technologies:
CKKS homomorphic encryption, a hardware enclave (SGX / SEV-SNP), and a zk-SNARK
attestation gate. The spec provides naming and topology but **no protocols,
parameters, key-management story, or threat model.**

This is not buildable "per the spec," and a stub that *looked* like working
crypto would be actively harmful — it would invite false trust in a system that
protects nothing. So:

- `NullCryptoShield` — dev/test only, pass-through, **no confidentiality**,
  warns on construction.
- `EnclaveCryptoShield` — raises `NotImplementedError` on construction.
- `Oracle(environment="production")` — refuses to start without a real shield.

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
