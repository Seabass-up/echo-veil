# Echo Veil v1.0: Core Product & Architecture Specification

> Source design document, preserved as the reference spec for this repository.
> Implementation status, assumptions, and deviations are tracked in
> `ARCHITECTURE_NOTES.md`.

## 1. System Topology & Tiered Storage

Echo Veil minimizes operational storage bloat and prevents retrieval
hallucination by decoupling active intent tracking from latent data lookup. The
architecture is segregated into three distinct layers:

### Level 1: Memory Vines (The Active Workspace)
 * **Technical Role:** In-memory context cache tracking real-time intent geometry.
 * **Hardware Allocation:** Capped runtime RAM (512MB–2GB per active node).
 * **Capacity Boundary:** Supports 200–400 concurrent active vines before triggering metabolic pruning.

### Level 2: Metadata Layer (The Latent Spore Network)
 * **Technical Role:** Sparse vector database maintaining global semantic coordinate maps. Stays low-compute via indexing.
 * **Latency Metric:** < 5 ms global lookup latency.
 * **Artifact Types:** Houses inactive anchors, global index trees, and **Fossilized Echoes**.

### Level 3: Latent Archive (The Deep Soil)
 * **Technical Role:** Scale-free cold storage tier housing raw chunk data and unindexed history.
 * **Scale:** Exabyte-viable data horizon.
 * **Compute Profile:** Zero active resource draw; accessed exclusively during high-fault escalations or deep brute-force semantic extraction.

## 2. Workspace Lifecycle & Metabolism

The active runtime environment enforces data minimalism through an automated,
multi-tiered eviction loop driven by thematic relevance rather than strict
chronology.

### The Core Decay Loop

Vines drift out of the active pool based on their **Proximity Score**, which
evaluates live conversational trajectory against a time-decay factor, where the
Seed Crystal Intent Vector (768-dim, normalized) is compared against the Vine
Anchor Vector and Δt is the elapsed time in hours since the vine was last
touched.

> NOTE: the original document references this formula but omits the equation.
> See `ARCHITECTURE_NOTES.md` §2 for the formula this implementation adopts.

```
[ RAM Capacity > 85% ] ──► Scan Non-Locked Active Vines ──► Evaluate Proximity Score
                                                                   │
                                                                   ▼
[ Eviction Archive ] ◄── Dissolve from RAM (Cycle 5+) ◄── Twilight State (Score < 0.42)
```

 * **The Twilight State:** When a vine's Proximity Score falls below 0.42, it enters a twilight state for **5 query cycles or 30 minutes** (whichever is longer). It undergoes **88% memory footprint compression** via immediate serialization, allowing it to instantly snap back to full vitality (+0.08 reinforcement bonus) if the user swings back to that topic before expiration.

### Workspace Modifications
 * **Amber Locks:** Users can explicitly isolate up to 12 concurrent high-frequency vines within protected crystalline memory buffers, rendering them immune to proximity decay.
 * **Multi-Focal Crests:** The system supports up to 3 active thematic focal points at once. Resource tracking shifts via a **Dynamic Tidal Flow Engine**, dedicating 70% of available cache to the active conversational window while pinning secondary and tertiary crests to a protective 18% and 12% framework respectively. If total system memory pressure breaches 90%, the allocation tightens to a **78/14/08** split to protect processing latency.

## 3. Data Tension Protocol (Conflict Architecture)

The system rejects binary data overwriting. When disparate data inputs collide
within a **Peer-Review Zone** (Strength Delta Δ ≤ 0.15), the Oracle spawns a
specialized **Conflict Vine** to preserve the structural tension.

### The Confidence Spectrum Matrix

| Confidence Range | Qualitative Indicator | Operational & UI Behavior |
|---|---|---|
| **≥ 0.85** | **Solid Vine Integration** | Seamless, authoritative delivery. |
| **0.70 - 0.84** | **Coherent Assembly** | Standard delivery; minor context gaps noted in footer. |
| **0.50 - 0.69** | **Fragmented Synthesis** | Triggers **Micro-Vine Assembly** layout. Explicitly notes inferential leaps. |
| **0.35 - 0.49** | **High Inferential Leaps** | Speculative reconstruction. Prompts explicit user override to display. |
| **< 0.35** | **Data Obscurity Fault** | Hard stop. Gates generation and surfaces the 3-pronged escalation menu. |

### Fossilization & Resurrection
 * **The Fossil Record:** When new high-confidence data stabilizes an active conflict, the Conflict Vine withers. Its architectural history is compressed into a **Fossilized Echo** text-and-metadata summary payload limited strictly to < 2 KB to preserve future-proof, model-agnostic records. Subsequent re-openings mutate the *same* historical artifact, creating an evolving timeline log.
 * **The Lazarus Loop:** If a newly introduced query matches a settled fossil anchor, the topic undergoes **Resurrection**. The text summaries are re-embedded, re-sprouting an active Level 1 Conflict Vine with a normalized, neutral **Baseline Alertness Score of 0.55** to ensure historical inertia cannot bias the evaluation of newly arriving data.

## 4. The Caretaker Subsystems

```
               [ Global Maintenance Loop ]
                            │
      ┌─────────────────────┼─────────────────────┐
      ▼                     ▼                     ▼
Intent Drift Detection   Cache Compression    Adaptive Refinement
(Windowed Centroid)      (Twilight Pruning)   (Off-Peak Upgrades)
```

### Intent Drift Detection Engine
To counter gradual contextual decay across conversational threads, the engine
measures drift against a **3-query moving average** evaluated directly against
the **established vector centroid of the active garden** rather than
single-prompt deltas. A tracking threshold of 0.38 paired with a 0.08
hysteresis buffer guarantees that passing comments or isolated sidebar
questions do not trigger jarring false-alarm notifications.

### Adaptive Background Loop
During low-traffic cycles, the system parses data faults and fossil footprints
to conduct automated maintenance. It bundles these tasks into a transparent,
front-facing **Gardener's Report** upon session re-entry, visualizing system
cleanup metrics via four primary designations: *Thriving Vines* (Active),
*Twilight Grove* (Hibernating), *Knotted Branches* (Conflicts), and *Ancient
Rings* (Fossilized Timeline). Under **Deeper Tending** mode, users pin target
focus spaces, allowing the engine to pull deep Level 3 chunks to proactively
rebuild high-risk data gaps before they are explicitly requested.

## 5. The Cryptographic Root Shield

The complete memory space is structurally isolated against external inspection,
scraping, or unwanted harness attachments via a multi-layered hardware and
mathematical barrier.

```
[ Ciphertext Space (RAM) ] ──► Homomorphic Dot Products (CKKS)
                                      │
                                      ▼
[ Trusted Boundary ]      ──► Decryption & Thresholding Inside Hardware Enclave
                                      ▲
                                      │ (Remote Attestation Gate)
[ Verification Gate ]     ──► zk-SNARK Identity Proof Validation
```

 * **Homomorphic Calculation (CKKS):** All 768-dimensional Vine Anchor Vectors are held and operated upon as obfuscated ciphertexts. By pre-normalizing vector lengths inside the enclave, complex cosine similarity evaluations reduce to simple, high-speed linear dot products executed directly in plaintext-blind RAM.
 * **Access Control Verification:** The engine restricts access to the vector workspace behind a **Zero-Knowledge Proof (ZKP) gate**. Requesting client frameworks must present an attested zk-SNARK proving valid user-key possession and host machine integrity before any operations are initiated. Keys remain permanently sealed inside the local CPU's hardware-isolated memory enclave (Intel SGX / AMD SEV-SNP).

> NOTE: Section 5 is NOT implemented in this repository. See
> `ARCHITECTURE_NOTES.md` §5 for the rationale and a phased path.
