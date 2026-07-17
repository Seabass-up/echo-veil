# Changelog

All notable changes to Echo Veil are documented here. The project follows
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- Added a keyboard skip link, visible focus states, canonical metadata, and a
  non-repeating screen-reader description to the product site.
- Added deterministic gateway unit tests and sanitized, status-aware Python
  gateway errors for easier integration troubleshooting.

### Security

- Enforced request and response limits while streaming at both the Cloudflare
  gateway and enclave origin, rather than after unbounded buffering.
- Added a deadline to authenticated health forwarding, bounded Access JWTs,
  stricter Cloudflare team-domain validation, and defensive API headers.
- Removed upstream response bodies from Python client exceptions so enclave or
  proxy details cannot be copied into application logs.

## [0.4.0] - 2026-07-15

### Added

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

### Security

- Production startup requires the enclave shield and fails closed when
  attestation, measurement, CKKS, hardware isolation, or the ZKP gate is absent.
- Secret generation, replay controls, bounded inputs, and encrypted key-transfer
  tooling are included and tested.

[Unreleased]: https://github.com/Seabass-up/echo-veil/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/Seabass-up/echo-veil/releases/tag/v0.4.0
