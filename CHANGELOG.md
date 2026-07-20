# Changelog

All notable changes to Echo Veil are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/Seabass-up/echo-veil/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Seabass-up/echo-veil/releases/tag/v0.4.0
