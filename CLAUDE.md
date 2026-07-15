This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.
Commands
Bashpip install -e ".[dev]"          # install with dev deps (pytest)
pytest -q                        # run all tests
pytest tests/test_oracle.py      # run a single test file
Runtime dependencies are numpy>=1.24 and cryptography>=42.0; durable SQLite
storage uses the Python standard library. No linter is configured.
Project Philosophy
Echo Veil is a tiered, intent-driven, metabolically balanced, and cryptographically private memory system for AI agents. It rejects traditional "remember everything" approaches in favor of wise remembering — minimal active resources, precise retrieval, organic lifecycle management, and radical transparency about uncertainty.
Core tenets:

The Seed Crystal is the persistent north star of current intent.
Memory behaves like a living garden: vines grow, rest, wither, and resurrect.
Data tension (contradictions) is preserved as historical value via Fossilized Echoes and Knowledge Paleontology.
Privacy is a first-class architectural primitive — the "shape of thought" must remain protected.

Architecture Overview
Echo Veil uses a strict three-layer design:

Level 1: Active Workspace (Memory Vines) — high-compute, intent-proximity managed, transactionally checkpointed when SQLiteStore is configured
Level 2: Metadata Index — Sparse vector map + Flash Vines + Fossilized Echoes
Level 3: Latent Archive (Library of Worlds) — Cold storage of raw chunks

Data flow:
textUser Query → Oracle.observe(intent)
                 ↓
          Drift Detection + Intent Vector Update
                 ↓
          Workspace (L1): Proximity scoring → Tidal Flow → Decay Cycle
                 ↓
          (if needed) Flash Vine / Conflict Vine / Lazarus Resurrection
                 ↓
          Oracle.sprout() or Oracle.answer() with ConfidenceBand
                 ↓
          (idle) BackgroundRefinementEngine → Gardener’s Report
Module Responsibilities

ModuleRoleoracle.pyMain facade. Exposes clean public API. Wires all subsystems.vine.pyVine and ConflictVine dataclasses. Lifecycle states + strength.workspace.pyL1 pool: pruning, Twilight, Amber Locks, Multi-Focal Tidal Flow (70/18/12), memory pressure enforcement.proximity.pyScoring logic: cosine_similarity + recency_bonusconflict.pyConflict detection, Peer-Review Zone, FossilizedEcho compression/resurrection (Lazarus Loop).drift.pyIntent Drift Engine: moving average against garden centroid, 0.38 threshold + 0.08 hysteresis.confidence.pyMaps scores → organic bands (Solid Vine Integration, Fragmented Synthesis, Data Obscurity Fault, etc.).caretaker.pyGenerates Gardener’s Report and manages background refinement.archive.pyTiered backend contracts plus in-memory reference implementations.persistence.pyDurable transactional SQLite L1/L2/L3 backend with LSH retrieval and restart recovery.crypto_shield.pyAES-GCM protection and fail-closed attested CKKS enclave/ZKP provider integration.vectors.pyCore math helpers (cosine, normalize, centroid, etc.).paleontology.py(Future) Exhume History, timeline rendering, knowledge evolution queries.
Key Constants (from full spec)

Twilight Threshold: 0.42
Twilight Grace: 5 query cycles AND 30 minutes (both conditions)
Reinforcement Bonus: +0.08 on reactivation
Amber Lock Cap: 12
Max Focal Crests: 3 (Dynamic Tidal Flow: 70/18/12 → 78/14/08 under pressure)
Drift Threshold: 0.38 (with 0.08 hysteresis)
Reconstruction Confidence Bands: Solid → Coherent → Fragmented Synthesis → High Inferential Leaps → Data Obscurity Fault

Important Implementation Notes

Pruning Priority: Intent-proximity first, chronological age as tiebreaker.
Conflict Handling: Always present Competing Growth Paths. Never silently overwrite.
Resurrection: Lazarus Loop uses normalized 0.55 baseline alertness + historical metadata.
Background Refinement: Runs during idle periods. Produces Gardener’s Report on next session start. Supports "Deeper Tending" mode (pinned Focus Areas + limited anticipation).
Cryptographic Shield:
Level 1/2 vectors must use CKKS Homomorphic Encryption.
All critical operations inside hardware enclave (SGX/SEV).
ZKP attestation required before any sensitive access.
NullCryptoShield is for development only. Production Oracle() must reject startup without real shield.


Still Missing / To Implement:

Distributed storage backend for deployments beyond local SQLite scale.
Concrete vendor transports and trust policies for each SGX/SEV-SNP deployment.
Paleontology UI components and interactive timeline.
User-configurable Focus Areas + Deeper Tending toggles.
Comprehensive test suite covering edge cases (context whiplash, mass resurrection, high memory pressure).
