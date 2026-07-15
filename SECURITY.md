# Security Policy

## Supported versions

Security fixes are provided for the latest released minor version. Pre-release
and development snapshots are supported on a best-effort basis.

## Reporting a vulnerability

Do not open a public issue for a suspected vulnerability. Use GitHub's
[private vulnerability reporting](https://github.com/Seabass-up/echo-veil/security/advisories/new)
to send a description, affected version or commit, reproduction steps, and the
potential impact.

You should receive an acknowledgment within five business days. Please allow
time for investigation and coordinated remediation before public disclosure.

## Release security model

Automated checks include CodeQL, Bandit, deterministic dangerous-primitive
policy, workflow analysis, secret and misconfiguration scanning, personal-metadata
and developer-machine-path rejection, dependency audits, locked dependencies,
digest-pinned container bases, release archive inspection, SBOM generation,
checksums, and GitHub artifact provenance.

These controls reduce risk but cannot prove that code is free of malicious
logic. Every release still requires human review of security-sensitive changes
and the GitHub repository protections listed in `docs/RELEASING.md`.
