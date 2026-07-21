# Changelog

All notable changes to Echo Veil are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Seabass-up/echo-veil/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Seabass-up/echo-veil/compare/v0.3.0...v0.5.0
[0.4.0]: https://github.com/Seabass-up/echo-veil/tree/08de0b2de7d5e63c82209c9afaa54450a2aaec15
