# Secure release process

Echo Veil releases are built from an existing annotated semantic-version tag.
The workflow creates a draft GitHub release so its artifacts can be reviewed
before publication. It does not deploy cloud infrastructure or publish to PyPI.

## One-time GitHub configuration

These controls live in GitHub and cannot be enforced by repository files alone:

1. Protect the default branch (`master`) with a ruleset that requires pull requests, at least one
   approval, CODEOWNER review, dismissal of stale approvals, approval after the
   latest push, resolved conversations, signed commits, and all CI/security
   checks. Block force pushes, deletions, and administrator bypass.
2. Require these checks: every `CI` job, every `Security` job, every `CodeQL`
   language, and `Dependency Review`.
3. Enable private vulnerability reporting, Dependabot alerts, secret scanning,
   push protection, and immutable releases.
4. Require full-length commit SHAs for GitHub Actions. Allow only the action
   owners referenced by the workflows.
5. Create a `release` environment restricted to tags matching `v*`. Require an
   independent reviewer and prevent self-review.
6. Protect tags matching `v*` from updates and deletion.

CodeQL, artifact attestations, and protected-environment reviewers are available
at no charge when the repository is public. A private repository requires the
applicable paid GitHub security and Enterprise features; the corresponding
workflows intentionally fail closed when those services are unavailable.

If PyPI publishing is added, configure a PyPI Trusted Publisher bound to the
`release` environment. Do not add a long-lived PyPI API token.

## Release checklist

1. Confirm the worktree contains only intended changes and all dependency lock
   updates have been reviewed.
2. Update the version in `pyproject.toml`, `src/echo_veil/__init__.py`,
   `.codex-plugin/plugin.json`,
   `integrations/claude-code/.claude-plugin/plugin.json`,
   `integrations/openclaw/package.json`,
   `integrations/openclaw/openclaw.plugin.json`, and
   `integrations/pi/package.json`.
3. Move the changelog entries from `Unreleased` into the new version section.
4. Run:

   ```bash
   uv lock --check
   uv sync --locked --extra dev --extra enclave-origin
   uv run ruff check src tests scripts examples
   uv run ruff format --check src tests scripts examples
   uv run mypy src/echo_veil src/echo_veil_origin scripts examples --ignore-missing-imports --no-error-summary
   uv run pytest -q
   python scripts/security_scan.py .
   python scripts/privacy_scan.py . --git-history
   python scripts/release_check.py
   cargo fmt --manifest-path crates/echo-veil-zkp/Cargo.toml -- --check
   cargo clippy --locked --all-targets --manifest-path crates/echo-veil-zkp/Cargo.toml -- -D warnings
   cargo test --locked --manifest-path crates/echo-veil-zkp/Cargo.toml
   npm --prefix cloudflare/enclave-gateway ci --ignore-scripts
   npm --prefix cloudflare/enclave-gateway audit --audit-level=high
   npm --prefix website ci --ignore-scripts
   npm --prefix website audit --audit-level=high
   npm --prefix website run lint
   npm --prefix website test
   npm --prefix integrations/openclaw ci --ignore-scripts
   npm --prefix integrations/openclaw audit --audit-level=high
   npm --prefix integrations/openclaw run plugin:validate
   npm --prefix integrations/openclaw test
   npm --prefix integrations/pi ci --ignore-scripts
   npm --prefix integrations/pi audit --audit-level=high
   npm --prefix integrations/pi run check
   npm --prefix integrations/pi test
   ```

   Also run `tests/test_agent_adapters.py`, validate the repository-root Codex
   plugin and Claude Code plugin with their current validators, and validate the
   Goose recipe with `goose recipe validate` before tagging. Hermes, OpenCode,
   Droid, and Pi should be smoke-tested in isolated temporary host profiles so
   release checks never mutate an operator's personal agent configuration.

5. Merge only after required checks and independent review pass.
6. Create and push an annotated tag from the protected release commit:

   ```bash
   git tag -a v0.4.0 -m "Echo Veil v0.4.0"
   git push origin v0.4.0
   ```

7. Manually run the `Release` workflow with that exact tag.
8. Verify the draft's changelog, wheel, sdist, SBOM, `SHA256SUMS`, and GitHub
   provenance attestation. Install the wheel in a clean environment.
9. Publish the draft only after review. With immutable releases enabled, the
   tag and assets become unchangeable after publication.

## Consumer verification

Download the release assets, then verify their hashes:

```bash
sha256sum --check SHA256SUMS
```

For a public repository, verify GitHub provenance with the GitHub CLI:

```bash
gh attestation verify echo_veil-0.4.0-py3-none-any.whl \
  --repo Seabass-up/echo-veil
```
